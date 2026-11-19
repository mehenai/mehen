import { afterEach, describe, expect, it } from "vitest"
import { setUpstreamFetch } from "../../src/relay/upstream.ts"
import { body, refusal } from "./workspace-journey.ts"
import { protectedJourney } from "./protected-journey.ts"

afterEach(() => setUpstreamFetch(null))

describe("protected runs through real dispatch", () => {
  for (const change of ["protect", "rotate", "revoke"] as const) it(`protected run: four-eyes, self refusal, second-manager approval, relay and ${change} invalidation`, async () => {
    const f = await protectedJourney()
    if (change === "protect") await body(await f.projectMutation(f.alex, f.work, "variable", { project: f.project.id, name: "TOKEN", env: "staging", item: "prod-key", field: "key", before: null }, `/projects/${f.project.id}/vars/TOKEN`))
    const approval = await f.askRun()
    await refusal(await f.request(`/api/w/northwind/approvals/${approval}/action`, f.alex, { decision: "approve" }), 403, { error: "forbidden", message: "You are not allowed to do that." })
    await f.approve(approval)
    const run = await f.run(approval)
    let sends = 0
    setUpstreamFetch(async request => { sends++; expect(request.headers.get("authorization")).toBe("Bearer sk-integration-not-a-real-secret"); return new Response("protected-upstream") })
    for (let i = 0; i < 2; i++) {
      const response = await f.relay(run)
      expect(response.status).toBe(200)
      expect(await response.text()).toBe("protected-upstream")
    }
    if (change === "rotate") await f.credential(f.tom, f.work, "prod-key", { kind: "workspace" })
    else if (change === "protect") await body(await f.projectMutation(f.alex, f.work, "environment", { project: f.project.id, env: "staging", protected: true, fourEyes: false, fences: [], before: { protected: false, fourEyes: false, fences: [] } }, `/projects/${f.project.id}/environments/staging`))
    else {
      const before = await f.snapshot(f.work)
      await f.sql(f.work, "CREATE TRIGGER integration_delete_failure BEFORE INSERT ON audit WHEN NEW.action='item.delete' BEGIN SELECT RAISE(ABORT,'injected delete audit failure'); END")
      await refusal(await f.signed("/api/w/northwind/items/prod-key/delete", f.tom, {}, { type: "item.delete", item: f.sharedCredential.id }, "northwind"), 500, { error: "internal", message: "Something went wrong inside the vault." })
      expect(await f.snapshot(f.work)).toEqual(before)
      await f.sql(f.work, "DROP TRIGGER integration_delete_failure")
      expect(await body(await f.signed("/api/w/northwind/items/prod-key/delete", f.tom, {}, { type: "item.delete", item: f.sharedCredential.id }, "northwind"))).toEqual({})
    }
    const refused = await f.relay(run)
    await refusal(refused, change === "revoke" ? 404 : 409, change === "revoke" ? { error: "not_found", message: "No live run for this machine." } : { error: "conflict", message: change === "rotate" ? "A run credential changed; start a new run." : "Access changed; ask for a new approval." })
    expect(sends).toBe(2)
    if (change === "rotate") expect(await f.sql(f.work, "SELECT config_rev FROM items WHERE slug='prod-key'")).toEqual([{ config_rev: 1 }])
    else expect(await f.sql(f.work, "SELECT revoked_at IS NOT NULL AS revoked FROM run_authorisations WHERE run=?", run.run)).toEqual([{ revoked: 1 }])
    if (change === "revoke") expect(await f.sql(f.work, "SELECT item,field FROM vars WHERE project=? AND env='prod'", f.project.id)).toEqual([{ item: null, field: null }])
  })
})

describe("atomic real-resource offboarding", () => {
  for (const owner of [true, false]) it(`offboarding: ${owner ? "co-owner notice" : "plain admin without notice"}, private deletion, consent invalidation and retained workspace reference`, async () => {
    const f = await protectedJourney()
    if (owner) await body(await f.memberChange(f.alex, f.work, f.tom.member!, "role", "owner"))
    const privateItem = await f.credential(f.tom, f.work, "tom-private", { kind: "member", member: f.tom.member! })
    const approval = await f.askRun()
    await f.approve(approval)
    const run = await f.run(approval)
    const tomMachine = await f.protectedMachine(f.tom, f.work)
    const pending = await f.askRun(tomMachine)
    const own = await body<{ pending: { detail?: { id: string } }[]; notices: unknown[] }>(await f.deviceCall(tomMachine, "/v1/pending"))
    expect(own.pending.map(entry => entry.detail?.id)).toEqual([pending])
    const other = await body<{ pending: { detail?: { id: string } }[] }>(await f.deviceCall(f.machine, "/v1/pending"))
    expect(other.pending.map(entry => entry.detail?.id)).toEqual([])
    const snapshot = () => f.snapshot(f.work)
    const before = await snapshot()
    await f.sql(f.work, "CREATE TRIGGER integration_remove_failure BEFORE INSERT ON audit WHEN NEW.action='member.remove' BEGIN SELECT RAISE(ABORT,'injected removal audit failure'); END")
    const failed = await f.memberChange(f.alex, f.work, f.tom.member!, "remove")
    expect(failed.status).toBe(500)
    expect(await snapshot()).toEqual(before)
    expect(await f.db.prepare("SELECT state FROM memberships WHERE id=?").bind(f.tom.member).first()).toEqual({ state: "member" })
    await f.sql(f.work, "DROP TRIGGER integration_remove_failure")
    const outboxBefore = await f.sql(f.work, "SELECT id FROM notice_outbox ORDER BY id")
    expect(await body(await f.memberChange(f.alex, f.work, f.tom.member!, "remove"))).toEqual({ removed: true, member: f.tom.member })
    expect(await f.sql(f.work, "SELECT status FROM members WHERE id=?", f.tom.member!)).toEqual([{ status: "removed" }])
    expect(await f.sql(f.work, "SELECT id FROM items WHERE id=?", privateItem.id)).toEqual([])
    expect(await f.sql(f.work, "SELECT item FROM item_secrets WHERE item=?", privateItem.id)).toEqual([])
    expect(await f.sql(f.work, "SELECT slug FROM items WHERE id=?", f.sharedCredential.id)).toEqual([{ slug: "prod-key" }])
    expect(await f.sql(f.work, "SELECT item,field FROM vars WHERE project=? AND env='prod'", f.project.id)).toEqual([{ item: "prod-key", field: "key" }])
    expect(await f.sql(f.work, "SELECT revoked_at IS NOT NULL AS revoked FROM run_authorisations WHERE run=?", run.run)).toEqual([{ revoked: 1 }])
    expect(await f.sql(f.work, "SELECT revoked_at IS NOT NULL AS revoked FROM consent_lineage WHERE decision=?", approval)).toEqual([{ revoked: 1 }])
    expect(await f.sql(f.work, "SELECT revoked_at IS NOT NULL AS revoked FROM protected_use_grants WHERE approval=?", approval)).toEqual([{ revoked: 1 }])
    let losingSends = 0
    setUpstreamFetch(async () => { losingSends++; return new Response("unexpected old run") })
    await refusal(await f.relay(run), 403, { error: "forbidden", message: "This use no longer has a current approval." })
    expect(losingSends).toBe(0)
    expect(await f.sql(f.work, "SELECT status FROM approvals WHERE id=?", pending)).toEqual([{ status: "denied" }])
    expect(await f.sql(f.work, "SELECT action,target FROM audit WHERE action='member.remove'")).toEqual([{ action: "member.remove", target: f.tom.member }])
    const outboxAfter = await f.sql<{ id: string; account: string; payload: string }>(f.work, "SELECT id,account,payload FROM notice_outbox ORDER BY id")
    const added = outboxAfter.filter(row => !outboxBefore.some(old => old.id === row.id))
    if (owner) {
      expect(added.map(row => row.account).sort()).toEqual([f.alex.account, f.tom.account].sort())
      for (const notice of added) expect(JSON.parse(notice.payload)).toEqual({ kind: "owner_changed", workspace: f.work, member: f.tom.member, name: "Tom", change: "removed", by: await f.member(f.alex, f.work), at: expect.any(String) })
    } else expect(added).toEqual([])
    // A new member's independently approved run still uses the retained ref.
    const noor = await f.guest(f.alex, f.work, f.project.id, "Noor")
    await body(await f.memberChange(f.alex, f.work, noor.member!, "role", "admin"))
    const noorMachine = await f.protectedMachine(noor, f.work)
    const next = await f.askRun(noorMachine)
    await f.approve(next, f.alex)
    const nextRun = await f.run(next, noorMachine)
    setUpstreamFetch(async () => new Response("retained-reference"))
    expect(await (await f.relay(nextRun, noorMachine)).text()).toBe("retained-reference")
  })
})
