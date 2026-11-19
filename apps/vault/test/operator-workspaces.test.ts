// The operator console's Workspaces view (routes/console-workspaces.ts,
// directory/operator-workspaces.ts) and its two proposal kinds, restoring
// and freezing a workspace (directory/operator-proposal-kinds.ts), through
// the real Worker with real web sessions and the real passkey step-up. The
// workspace objects are a stand-in recording every call; the objects' own
// system calls are tested in operator-workspace-object.test.ts.

import { describe, expect, it } from "vitest"
import { type OperatorProposalAnswer, type OperatorProposalTerms, type OperatorWorkspaceDetail, type OperatorWorkspaceList, NEEDS_SECOND_OPERATOR_WORDS, OPERATOR_WORKSPACES_PAGE_SIZE, operatorApproveStepUpAction, operatorProposalDigest, operatorProposeStepUpAction, operatorRequirementsRefusal } from "@mehen/protocol"
import { STANDING_CHANGED, approveOperatorProposal, proposeOperatorChange } from "../src/directory/operator-proposals.ts"
import { restoreIntentDigest, runVaultRestores, type VaultBackupClient } from "../src/directory/vault-backups.ts"
import { type ConsoleFixture, type Person, answer, consoleFixture } from "./console-support.ts"
import { DEFAULT_WORKSPACE_ANSWER, type WorkspaceAnswer } from "./platform-fixtures.ts"

const HIDDEN = { error: "not_found", message: "No such operation." }
const OPERATOR_START = "/api/operator/stepup/start"
const WORK = "tn_Beta1234567"
const PERSONAL = "tn_Alpha123456"

// What happens elsewhere while a stand-in object freezes, once.
type Meanwhile = { freezing: (() => Promise<void>) | null }

// The stand-in objects: each answers its operator view (frozen or not, its
// one owner, one unconfirmed person) and freezes when asked, telling its
// owner and admin.
function objects(frozen: Set<string>, meanwhile: Meanwhile): WorkspaceAnswer {
  return async (call) => {
    if (call.op === "access.operator_view") return { ok: true, value: { frozen: frozen.has(call.tenant), owners: [{ account: "acc_owner", name: "Owner in the workspace" }], unconfirmed: 1 } }
    if (call.op === "access.operator_freeze") {
      const run = meanwhile.freezing
      meanwhile.freezing = null
      await run?.()
      const already = frozen.has(call.tenant)
      frozen.add(call.tenant)
      return { ok: true, value: { frozen: true, already, notify: ["acc_owner", "acc_admin"] } }
    }
    return DEFAULT_WORKSPACE_ANSWER(call)
  }
}

type Setup = ConsoleFixture & { kim: Person; gus: Person; owner: Person; frozen: Set<string>; meanwhile: Meanwhile }

// Kim and Gus are operators, each with everything an operator account
// needs; the workspaces' owner is not.
async function setup(operators: "two" | "one" = "two"): Promise<Setup> {
  const frozen = new Set<string>()
  const meanwhile: Meanwhile = { freezing: null }
  const f = await consoleFixture(objects(frozen, meanwhile))
  await f.grantOperator("acc_kim")
  if (operators === "two") await f.grantOperator("acc_guest")
  return { ...f, frozen, meanwhile, kim: await f.person("acc_kim"), gus: await f.person("acc_guest"), owner: await f.person("acc_owner") }
}

async function propose(f: ConsoleFixture, who: Person, terms: OperatorProposalTerms): Promise<Response> {
  const stepUp = await f.proof(who, OPERATOR_START, await operatorProposeStepUpAction(terms))
  return f.request("/api/operator/proposals", who, { ...terms, stepUp })
}

async function approve(f: ConsoleFixture, who: Person, proposal: { id: string; digest: string }): Promise<Response> {
  const stepUp = await f.proof(who, OPERATOR_START, operatorApproveStepUpAction(proposal.id, proposal.digest))
  return f.request(`/api/operator/proposals/${proposal.id}`, who, { decision: "approve", digest: proposal.digest, stepUp })
}

async function refused(response: Response, status: number, message: string): Promise<void> {
  expect({ status: response.status, message: ((await response.json()) as { message: string }).message }).toEqual({ status, message })
}

async function noticed(f: ConsoleFixture, kind: string, event: string): Promise<string[]> {
  const rows = await f.env.DB.prepare("SELECT account FROM account_notices WHERE json_extract(payload,'$.change')='operator_proposal' AND json_extract(payload,'$.kind')=? AND json_extract(payload,'$.event')=? ORDER BY account").bind(kind, event).all<{ account: string }>()
  return rows.results.map((row) => row.account)
}

function restoreTerms(target: string, params: Record<string, unknown>): OperatorProposalTerms {
  return { kind: "workspace.restore", target, params }
}

describe("the Workspaces view", () => {
  it("is not_found to anyone but an operator, like every operator route", async () => {
    const f = await setup()
    for (const path of ["/api/operator/workspaces", `/api/operator/workspaces/${WORK}`]) {
      for (const who of [f.owner, undefined]) {
        const response = await f.request(path, who)
        expect({ status: response.status, body: await response.json() }).toEqual({ status: 404, body: HIDDEN })
      }
    }
    expect(f.calls).toEqual([])
  })

  it("lists every workspace with its owners from the object, its members counted from memberships, and who created it", async () => {
    const f = await setup()
    const list = await answer<OperatorWorkspaceList>(await f.request("/api/operator/workspaces", f.kim))
    expect(list.filter).toBe("all")
    expect(list.workspaces.map((w) => w.id).sort()).toEqual([PERSONAL, WORK])
    const work = list.workspaces.find((w) => w.id === WORK)
    expect(work).toEqual({ kind: "workspace", id: WORK, slug: "northwind", name: "Work", status: "active", owners: [{ account: "acc_owner", name: "owner" }], members: 5, createdBy: { account: "acc_owner", name: "owner" }, createdAt: expect.any(String) })
    // The joining person counts as a member of the personal workspace.
    expect(list.workspaces.find((w) => w.id === PERSONAL)).toMatchObject({ members: 2 })
    expect(f.calls.map((c) => [c.tenant, c.op, c.auth.kind]).sort()).toEqual([[PERSONAL, "access.operator_view", "system"], [WORK, "access.operator_view", "system"]])
  })

  it("searches by part of a name or slug, or a whole id, and filters by status", async () => {
    const f = await setup()
    await f.env.DB.prepare("UPDATE workspaces SET status='deleting',delete_after=? WHERE id=?").bind(Date.now() + 86_400_000, PERSONAL).run()
    const ids = async (query: string) => (await answer<OperatorWorkspaceList>(await f.request(`/api/operator/workspaces${query}`, f.kim))).workspaces.map((w) => w.id)
    expect(await ids("?q=wind")).toEqual([WORK])
    expect(await ids("?q=WOR")).toEqual([WORK])
    expect(await ids(`?q=${PERSONAL}`)).toEqual([PERSONAL])
    expect(await ids("?q=tn_Alpha")).toEqual([])
    expect(await ids("?q=%25")).toEqual([])
    expect(await ids("?filter=deleting")).toEqual([PERSONAL])
    expect(await ids("?filter=active")).toEqual([WORK])
    expect(await ids("?filter=creating")).toEqual([])
    const bad = await f.request("/api/operator/workspaces?filter=everything", f.kim)
    expect(bad.status).toBe(400)
  })

  it("lists the platforms' managed workspaces apart, by platform and never by subject", async () => {
    const f = await setup()
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO platforms (id,slug,name,status,limits,defaults,defaults_rev,created_at,created_by,status_at,status_by) VALUES ('plt_globex','globex','Globex','active','{}','{}',1,1,'operator:test',1,'operator:test')"),
      f.env.DB.prepare("INSERT INTO managed_workspaces (tenant,platform,subject,subject_hash,status,created_at) VALUES ('tn_Managed12345','plt_globex','user-secret','hash','active',?)").bind(Date.now()),
    ])
    const list = await answer<OperatorWorkspaceList>(await f.request("/api/operator/workspaces?filter=managed", f.kim))
    expect(list.workspaces).toEqual([{ kind: "managed", id: "tn_Managed12345", platform: { id: "plt_globex", slug: "globex", name: "Globex" }, status: "active", createdAt: expect.any(String) }])
    expect(JSON.stringify(list)).not.toContain("user-secret")
    expect((await answer<OperatorWorkspaceList>(await f.request("/api/operator/workspaces", f.kim))).workspaces.map((w) => w.id)).not.toContain("tn_Managed12345")
  })

  it("reads a page at a time, newest first, with a cursor to the next", async () => {
    const f = await setup()
    const base = Date.now() - 1_000_000
    await f.env.DB.batch(Array.from({ length: OPERATOR_WORKSPACES_PAGE_SIZE }, (_, i) => f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,?,?,'creating','acc_owner',?)").bind(`tn_Page${String(i).padStart(8, "0")}`, `page-${i}`, `Page ${i}`, base + i)))
    const first = await answer<OperatorWorkspaceList>(await f.request("/api/operator/workspaces", f.kim))
    expect(first.workspaces).toHaveLength(OPERATOR_WORKSPACES_PAGE_SIZE)
    expect(first.next).not.toBeNull()
    const second = await answer<OperatorWorkspaceList>(await f.request(`/api/operator/workspaces?before=${encodeURIComponent(first.next!)}`, f.kim))
    expect([...first.workspaces, ...second.workspaces].map((w) => w.id)).toHaveLength(OPERATOR_WORKSPACES_PAGE_SIZE + 2)
    expect(new Set([...first.workspaces, ...second.workspaces].map((w) => w.id)).size).toBe(OPERATOR_WORKSPACES_PAGE_SIZE + 2)
    expect(second.next).toBeNull()
    // Only an active workspace's object is asked: a creating one may not exist yet.
    expect(f.calls.filter((c) => c.tenant.startsWith("tn_Page"))).toEqual([])
  })

  it("shows one workspace: its slugs, people by role and unconfirmed, backups, restores and its operator events", async () => {
    const f = await setup()
    const now = Date.now()
    const day = (ago: number) => new Date(now - ago * 86_400_000).toISOString().slice(0, 10)
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO workspace_slugs(slug,workspace,retired_at) VALUES ('old-work',?,?)").bind(WORK, now - 5000),
      f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,?,'ok',1234,?,1,?)").bind(WORK, day(2), "a".repeat(64), now - 2 * 86_400_000),
      f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,error,attempts,attempted_at) VALUES (?,?,'failed','too_large: big',2,?)").bind(WORK, day(1), now - 86_400_000),
      f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,?,'ok',1,?,1,?)").bind(WORK, day(60), "b".repeat(64), now - 60 * 86_400_000),
      f.env.DB.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at,state,completed_at) VALUES (?,?,'dump',?,'operator:alex','h',?,?,'done',?)").bind(`vri_${"1".repeat(32)}`, WORK, day(2), now - 9000, now - 9000 + 3_600_000, now - 8000),
      f.env.DB.prepare("INSERT INTO deployment_events(id,at,kind,actor,approver,target,details) VALUES ('dpe_mine',?,'workspace.freeze','operator:acc_kim',NULL,?,'{}'),('dpe_other',?,'operator.grant','operator:acc_kim',NULL,'acc_admin','{}')").bind(now, WORK, now),
    ])
    const d = await answer<OperatorWorkspaceDetail>(await f.request(`/api/operator/workspaces/${WORK}`, f.kim))
    expect(d.workspace).toMatchObject({ id: WORK, slug: "northwind", name: "Work", status: "active", frozen: false, createdBy: { account: "acc_owner", name: "owner" }, deleteAfter: null, displayRevision: 1, slugs: [{ slug: "old-work", retiredAt: expect.any(String) }] })
    expect(d.people).toEqual({ owners: [{ account: "acc_owner", name: "owner" }], roles: { owner: 1, admin: 1, member: 2, guest: 1 }, joining: 0, unconfirmed: 1 })
    expect(d.backups.lastDump).toMatchObject({ date: day(2), bytes: 1234, rootVersion: 1 })
    expect(d.backups.lastFailure).toEqual({ date: day(1), error: "too_large: big", attempts: 2 })
    // A dump older than 35 days is listed only when it is the first of a month.
    expect(d.backups.dumps).toEqual(day(60).endsWith("-01") ? [day(2), day(60)] : [day(2)])
    expect(d.backups.restores).toEqual([{ id: `vri_${"1".repeat(32)}`, source: "dump", target: day(2), actor: "operator:alex", state: "done", createdAt: expect.any(String), completedAt: expect.any(String), error: null }])
    expect(d.events.map((e) => e.id)).toEqual(["dpe_mine"])
    expect({ operators: d.operators, missing: d.missing, restore: d.restore }).toEqual({ operators: 2, missing: [], restore: null })
    expect(JSON.stringify(d)).not.toMatch(/credential|project|member:mem_/)
    await f.request(`/api/operator/workspaces/tn_Nowhere1234`, f.kim).then((r) => expect(r.status).toBe(404))
    await f.request("/api/operator/workspaces/acc_owner", f.kim).then((r) => expect(r.status).toBe(404))
  })

  it("still shows what the directory holds when the object does not answer", async () => {
    const f = await consoleFixture((call) => (call.op === "access.operator_view" ? { ok: false, error: { status: 503, vaultError: { error: "upstream_failed", message: "Down." } } } : DEFAULT_WORKSPACE_ANSWER(call)))
    await f.grantOperator("acc_kim")
    const kim = await f.person("acc_kim")
    const d = await answer<OperatorWorkspaceDetail>(await f.request(`/api/operator/workspaces/${WORK}`, kim))
    expect({ frozen: d.workspace.frozen, owners: d.people.owners, unconfirmed: d.people.unconfirmed, roles: d.people.roles }).toEqual({ frozen: null, owners: null, unconfirmed: null, roles: { owner: 1, admin: 1, member: 2, guest: 1 } })
    const list = await answer<OperatorWorkspaceList>(await f.request("/api/operator/workspaces", kim))
    expect(list.workspaces.every((w) => w.kind === "workspace" && w.owners === null)).toBe(true)
  })
})

describe("restoring a workspace", () => {
  it("needs a second operator, and says so before any passkey", async () => {
    const f = await setup("one")
    const terms = restoreTerms(WORK, { source: "pitr", target: new Date(Date.now() - 3_600_000).toISOString() })
    await refused(await f.request("/api/operator/proposals", f.kim, { ...terms }), 403, NEEDS_SECOND_OPERATOR_WORDS.change)
  })

  it("approved by a second operator, records exactly the intent the script records, which the cron then carries out", async () => {
    const f = await setup()
    const point = new Date(Date.now() - 3_600_000).toISOString()
    const terms = restoreTerms(WORK, { source: "pitr", target: point })
    const proposed = await answer<OperatorProposalAnswer>(await propose(f, f.kim, terms), 201)
    expect(proposed.proposal).toMatchObject({ kind: "workspace.restore", target: WORK, targetName: "Work", params: { source: "pitr", target: point }, awaiting: "approval" })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM vault_restore_intents").first()).toEqual({ n: 0 })
    const detail = await answer<OperatorWorkspaceDetail>(await f.request(`/api/operator/workspaces/${WORK}`, f.gus))
    expect(detail.restore).toMatchObject({ id: proposed.proposal!.id })
    const before = Date.now()
    const approved = await answer<OperatorProposalAnswer>(await approve(f, f.gus, proposed.proposal!))
    expect(approved.done).toBe("Approved. The restore of Work is recorded, and the cron carries it out within the hour. Its owners re-apply what it undid, then unfreeze it.")
    const row = await f.env.DB.prepare("SELECT id,tenant,source,target,actor,intent_hash,created_at,expires_at,state FROM vault_restore_intents").first<{ id: string; tenant: string; source: "pitr"; target: string; actor: string; intent_hash: string; created_at: number; expires_at: number; state: string }>()
    expect(row).toMatchObject({ id: expect.stringMatching(/^vri_[a-f0-9]{32}$/), tenant: WORK, source: "pitr", target: point, actor: "operator:acc_kim", state: "pending" })
    expect(row!.created_at).toBeGreaterThanOrEqual(before)
    expect(row!.expires_at).toBe(row!.created_at + 3_600_000)
    expect(row!.intent_hash).toBe(await restoreIntentDigest({ id: row!.id, tenant: row!.tenant, source: row!.source, target: row!.target, actor: row!.actor, createdAt: row!.created_at }))
    const events = await f.env.DB.prepare("SELECT kind,actor,approver,target FROM deployment_events WHERE target=? ORDER BY at,rowid").bind(WORK).all()
    expect(events.results).toEqual([{ kind: "proposal.open", actor: "operator:acc_kim", approver: null, target: WORK }, { kind: "workspace.restore", actor: "operator:acc_kim", approver: "operator:acc_guest", target: WORK }])
    // The approval names the intent it recorded.
    const applied = await f.env.DB.prepare("SELECT details FROM deployment_events WHERE kind='workspace.restore'").first<{ details: string }>()
    expect(JSON.parse(applied!.details)).toEqual({ proposal: proposed.proposal!.id, digest: proposed.proposal!.digest, intent: row!.id })
    // Every operator and the workspace's owner.
    expect(await noticed(f, "workspace.restore", "applied")).toEqual(["acc_guest", "acc_kim", "acc_owner"])
    // The cron takes it as it takes the script's.
    const staged: string[] = []
    const client: VaultBackupClient = {
      dump: async () => { throw new Error("unused") },
      restore: async (tenant, input) => { staged.push(`${tenant} ${input.source} ${input.source === "pitr" ? input.at : input.date}`); return { source: "pitr", at: point, bookmark: "bm", undoBookmark: "undo" } },
      restart: async () => {},
      restored: async () => {},
    }
    await runVaultRestores(f.env, client)
    expect(staged).toEqual([`${WORK} pitr ${point}`])
    expect(await f.env.DB.prepare("SELECT state,bookmark,undo_bookmark FROM vault_restore_intents").first()).toEqual({ state: "done", bookmark: "bm", undo_bookmark: "undo" })
  })

  it("from a dump, only of a day with a recorded good dump", async () => {
    const f = await setup()
    const date = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10)
    await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms(WORK, { source: "dump", target: date })), 409, "There is no recorded dump of that workspace on that day.")
    await f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,?,'ok',10,?,1,?)").bind(WORK, date, "c".repeat(64), Date.now()).run()
    const proposed = await answer<OperatorProposalAnswer>(await propose(f, f.kim, restoreTerms(WORK, { source: "dump", target: date })), 201)
    await answer(await approve(f, f.gus, proposed.proposal!))
    expect(await f.env.DB.prepare("SELECT source,target,actor FROM vault_restore_intents").first()).toEqual({ source: "dump", target: date, actor: "operator:acc_kim" })
  })

  it("refuses a point outside the last 30 days, a malformed one, another workspace's id, and a second restore in progress", async () => {
    const f = await setup()
    await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms(WORK, { source: "pitr", target: new Date(Date.now() - 31 * 86_400_000).toISOString() })), 409, "A point-in-time restore reaches back at most 30 days, and not into the future.")
    await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms(WORK, { source: "pitr", target: new Date(Date.now() + 60_000).toISOString() })), 409, "A point-in-time restore reaches back at most 30 days, and not into the future.")
    await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms(WORK, { source: "pitr", target: "2026-10-31T08:15:00+01:00" })), 400, "Those are not the terms of workspace.restore.")
    await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms("acc_owner", { source: "pitr", target: new Date().toISOString() })), 400, "That is not a workspace id (tn_...).")
    await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms("tn_Nowhere1234", { source: "pitr", target: new Date(Date.now() - 60_000).toISOString() })), 404, "No workspace has that id.")
    const now = Date.now()
    await f.env.DB.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at) VALUES (?,?,'pitr',?,'operator:alex','h',?,?)").bind(`vri_${"2".repeat(32)}`, WORK, new Date(now - 60_000).toISOString(), now, now + 3_600_000).run()
    await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms(WORK, { source: "pitr", target: new Date(now - 60_000).toISOString() })), 409, `Restore vri_${"2".repeat(32)} of this workspace is still in progress.`)
  })

  it("refuses a workspace being created, being deleted or deleted, when proposed, when approved and in the approval's batch", async () => {
    const f = await setup()
    const point = () => new Date(Date.now() - 3_600_000).toISOString()
    for (const status of ["creating", "deleting", "deleted"]) {
      await f.env.DB.prepare("UPDATE workspaces SET status=?,delete_after=? WHERE id=?").bind(status, Date.now() + 86_400_000, PERSONAL).run()
      await refused(await f.request("/api/operator/proposals", f.kim, restoreTerms(PERSONAL, { source: "pitr", target: point() })), 409, `Personal is ${status}; only an active workspace is restored.`)
    }
    const proposed = await answer<OperatorProposalAnswer>(await propose(f, f.kim, restoreTerms(WORK, { source: "pitr", target: point() })), 201)
    await f.env.DB.prepare("UPDATE workspaces SET status='deleting',delete_after=? WHERE id=?").bind(Date.now() + 86_400_000, WORK).run()
    await refused(await approve(f, f.gus, proposed.proposal!), 409, "Work is deleting; only an active workspace is restored.")
    await f.env.DB.prepare("UPDATE workspaces SET status='active',delete_after=NULL WHERE id=?").bind(WORK).run()
    const deleting = () => f.env.DB.prepare("UPDATE workspaces SET status='deleting',delete_after=? WHERE id=?").bind(Date.now() + 86_400_000, WORK).run()
    await expect(approveOperatorProposal(f.env, "acc_guest", proposed.proposal!.id, proposed.proposal!.digest, deleting)).rejects.toThrow("Nothing changed: the proposal or an operator changed while this ran. Read it again.")
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM vault_restore_intents").first()).toEqual({ n: 0 })
  })

  it("is not applied when a restore of the workspace started after it was proposed", async () => {
    const f = await setup()
    const point = new Date(Date.now() - 3_600_000).toISOString()
    const proposed = await answer<OperatorProposalAnswer>(await propose(f, f.kim, restoreTerms(WORK, { source: "pitr", target: point })), 201)
    const now = Date.now()
    await f.env.DB.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at) VALUES (?,?,'pitr',?,'operator:alex','h',?,?)").bind(`vri_${"3".repeat(32)}`, WORK, point, now, now + 3_600_000).run()
    await refused(await approve(f, f.gus, proposed.proposal!), 409, `Restore vri_${"3".repeat(32)} of this workspace is still in progress.`)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM vault_restore_intents").first()).toEqual({ n: 1 })
  })

  it("is not applied when, after the approval's checks and during its passkey, a restore of the workspace starts or the dump's record goes", async () => {
    const f = await setup()
    const point = new Date(Date.now() - 3_600_000).toISOString()
    const pitr = await answer<OperatorProposalAnswer>(await propose(f, f.kim, restoreTerms(WORK, { source: "pitr", target: point })), 201)
    const started = async () => {
      const now = Date.now()
      await f.env.DB.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at) VALUES (?,?,'pitr',?,'operator:alex','h',?,?)").bind(`vri_${"4".repeat(32)}`, WORK, point, now, now + 3_600_000).run()
    }
    await expect(approveOperatorProposal(f.env, "acc_guest", pitr.proposal!.id, pitr.proposal!.digest, started)).rejects.toThrow("Nothing changed: the proposal or an operator changed while this ran. Read it again.")
    expect((await f.env.DB.prepare("SELECT id FROM vault_restore_intents").all()).results).toEqual([{ id: `vri_${"4".repeat(32)}` }])

    const date = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10)
    await f.env.DB.prepare("INSERT INTO vault_backup_runs(tenant,date,outcome,bytes,sha256,root_version,attempted_at) VALUES (?,?,'ok',10,?,1,?)").bind(PERSONAL, date, "d".repeat(64), Date.now()).run()
    const dump = await answer<OperatorProposalAnswer>(await propose(f, f.kim, restoreTerms(PERSONAL, { source: "dump", target: date })), 201)
    const removed = () => f.env.DB.prepare("DELETE FROM vault_backup_runs WHERE tenant=? AND date=?").bind(PERSONAL, date).run()
    await expect(approveOperatorProposal(f.env, "acc_guest", dump.proposal!.id, dump.proposal!.digest, removed)).rejects.toThrow("Nothing changed: the proposal or an operator changed while this ran. Read it again.")
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM vault_restore_intents WHERE tenant=?").bind(PERSONAL).first()).toEqual({ n: 0 })
  })
})

describe("freezing a workspace", () => {
  it("one operator with a passkey freezes it through the object's own freeze, recorded as theirs, and its owners, admins and every operator are told", async () => {
    const f = await setup()
    const terms: OperatorProposalTerms = { kind: "workspace.freeze", target: WORK, params: {} }
    // Without its passkey it is refused, and the object is never asked.
    await refused(await f.request("/api/operator/proposals", f.kim, terms), 403, "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again.")
    expect(f.calls.filter((c) => c.op === "access.operator_freeze")).toEqual([])
    const done = await answer<OperatorProposalAnswer>(await propose(f, f.kim, terms))
    expect(done).toEqual({ done: "Work is frozen. Its owners unfreeze it from its home page, with a passkey.", proposal: null })
    expect(f.calls.filter((c) => c.op === "access.operator_freeze")).toEqual([{ tenant: WORK, op: "access.operator_freeze", input: { operator: "acc_kim" }, auth: { kind: "system", reason: "operator console" } }])
    expect(await f.env.DB.prepare("SELECT kind,actor,approver,target FROM deployment_events WHERE target=?").bind(WORK).all().then((r) => r.results)).toEqual([{ kind: "workspace.freeze", actor: "operator:acc_kim", approver: null, target: WORK }])
    expect(await noticed(f, "workspace.freeze", "applied")).toEqual(["acc_admin", "acc_guest", "acc_kim", "acc_owner"])
    expect((await answer<OperatorWorkspaceDetail>(await f.request(`/api/operator/workspaces/${WORK}`, f.kim))).workspace.frozen).toBe(true)
  })

  it("reads the operator and the workspace again after the passkey, and freezes nothing when either changed", async () => {
    const f = await setup()
    const terms: OperatorProposalTerms = { kind: "workspace.freeze", target: WORK, params: {} }
    await expect(proposeOperatorChange(f.env, "acc_kim", terms, await operatorProposalDigest(terms), () => f.revokeOperator("acc_kim"))).rejects.toThrow(STANDING_CHANGED)
    await expect(proposeOperatorChange(f.env, "acc_guest", terms, await operatorProposalDigest(terms), async () => { f.frozen.add(WORK) })).rejects.toThrow("Work is frozen already.")
    expect(f.calls.filter((c) => c.op === "access.operator_freeze")).toEqual([])
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM deployment_events WHERE target=?").bind(WORK).first()).toEqual({ n: 0 })
  })

  it("once frozen, is recorded even when the operator or the workspace changed meanwhile, marked unguarded with why", async () => {
    const f = await setup()
    f.meanwhile.freezing = () => f.revokeOperator("acc_kim")
    const done = await answer<OperatorProposalAnswer>(await propose(f, f.kim, { kind: "workspace.freeze", target: WORK, params: {} }))
    expect(done).toEqual({ done: "Work is frozen. Its owners unfreeze it from its home page, with a passkey. Your standing as an operator changed while this ran, so its record is marked unguarded.", proposal: null })
    f.meanwhile.freezing = async () => { await f.env.DB.prepare("UPDATE workspaces SET status='deleting',delete_after=? WHERE id=?").bind(Date.now() + 86_400_000, PERSONAL).run() }
    expect((await answer<OperatorProposalAnswer>(await propose(f, f.gus, { kind: "workspace.freeze", target: PERSONAL, params: {} }))).done).toBe("Personal is frozen. Its owners unfreeze it from its home page, with a passkey. Its target changed while this ran, so its record is marked unguarded.")
    const events = await f.env.DB.prepare("SELECT kind,actor,target,details FROM deployment_events WHERE kind='workspace.freeze' ORDER BY target").all<{ details: string }>()
    expect(events.results.map((e) => ({ ...e, details: JSON.parse(e.details) }))).toEqual([
      { kind: "workspace.freeze", actor: "operator:acc_guest", target: PERSONAL, details: { digest: await operatorProposalDigest({ kind: "workspace.freeze", target: PERSONAL, params: {} }), unguarded: true, reason: "target-changed" } },
      { kind: "workspace.freeze", actor: "operator:acc_kim", target: WORK, details: { digest: await operatorProposalDigest({ kind: "workspace.freeze", target: WORK, params: {} }), unguarded: true, reason: "operator-changed" } },
    ])
    // The operators as the role stands, and each workspace's owner and admin, twice.
    expect(await noticed(f, "workspace.freeze", "applied")).toEqual(["acc_admin", "acc_admin", "acc_guest", "acc_guest", "acc_owner", "acc_owner"])
  })

  it("records nothing when an owner froze it first, and says it was frozen already", async () => {
    const f = await setup()
    f.meanwhile.freezing = async () => { f.frozen.add(WORK) }
    await refused(await propose(f, f.kim, { kind: "workspace.freeze", target: WORK, params: {} }), 409, "Work is frozen already.")
    expect(f.calls.filter((c) => c.op === "access.operator_freeze")).toHaveLength(1)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM deployment_events WHERE target=?").bind(WORK).first()).toEqual({ n: 0 })
    expect(await noticed(f, "workspace.freeze", "applied")).toEqual([])
  })

  it("refuses a frozen workspace, and one that is not active, before any passkey", async () => {
    const f = await setup()
    f.frozen.add(WORK)
    await refused(await f.request("/api/operator/proposals", f.kim, { kind: "workspace.freeze", target: WORK, params: {} }), 409, "Work is frozen already.")
    await f.env.DB.prepare("UPDATE workspaces SET status='deleting',delete_after=? WHERE id=?").bind(Date.now() + 86_400_000, PERSONAL).run()
    await refused(await f.request("/api/operator/proposals", f.kim, { kind: "workspace.freeze", target: PERSONAL, params: {} }), 409, "Personal is deleting, so there is nothing to freeze.")
    expect(f.calls.filter((c) => c.op === "access.operator_freeze")).toEqual([])
  })

  it("needs an operator account with every requirement met, though it needs no second operator", async () => {
    const f = await setup("one")
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_kim'").run()
    await refused(await f.request("/api/operator/proposals", f.kim, { kind: "workspace.freeze", target: WORK, params: {} }), 403, operatorRequirementsRefusal(["security-key"]))
    expect(f.calls.filter((c) => c.op === "access.operator_freeze")).toEqual([])
    // With a security key again, Kim, the only operator, freezes it alone.
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"usb\"]' WHERE account='acc_kim'").run()
    expect((await answer<OperatorProposalAnswer>(await propose(f, f.kim, { kind: "workspace.freeze", target: WORK, params: {} }))).proposal).toBeNull()
  })
})
