import { expect, it } from "vitest"
import { restoreIntentDigest } from "../../src/directory/vault-backups.ts"
import { body, refusal, workJourney } from "./workspace-journey.ts"

// A restore rolls a workspace object back, its copy of each account's
// security with it, while the directory keeps the facts it already
// delivered. The cron run that records the restore puts the account's
// cooling-off and its ended sessions back in the object: a recovered
// account's machine cannot widen during cooling-off because a restore
// forgot it.
it("a restored workspace gets the account's cooling-off and ended sessions back from the directory", async () => {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  const before = await f.sql<{ account: string; state: string }>(f.work, "SELECT account,state FROM account_security WHERE account=?", f.alex.account)
  const plain = (value: string) => f.deviceCall(machine, `/v1/projects/${f.project.id}/vars/RESTORE_MARKER`, { env: "dev", plain: value }, undefined, undefined, "PUT")
  await body(await plain("before"))
  // A session ended after the restore point, delivered before the restore.
  const ended = { ...f.alex }
  await f.signin(ended)
  const endedSession = await f.db.prepare("SELECT id FROM web_sessions WHERE account=? ORDER BY created_at DESC LIMIT 1").bind(f.alex.account).first<{ id: string }>()
  await body(await f.request("/api/auth/signout", ended, {}))
  // Recovery commits, and its cooling-off reaches the workspace.
  expect(await body(await f.request("/api/auth/recovery", undefined, { code: f.alex.codes[0] }))).toEqual({ pending: false, transition: expect.stringMatching(/^trn_/) })
  await f.db.prepare("UPDATE account_events SET next_retry_at=0").run()
  await f.cron()
  const account = await f.db.prepare("SELECT security_epoch,restricted_until,restricted_reason FROM accounts WHERE id=?").bind(f.alex.account).first<{ security_epoch: number; restricted_until: number; restricted_reason: string }>()
  const delivered = async () => {
    const [row] = await f.sql<{ state: string }>(f.work, "SELECT state FROM account_security WHERE account=?", f.alex.account)
    return JSON.parse(row!.state) as { installedEpoch: number; restriction: { reason: string; until: number } | null; revokedSessionIds: string[] }
  }
  expect(await delivered()).toMatchObject({ installedEpoch: account!.security_epoch, restriction: { reason: account!.restricted_reason, until: account!.restricted_until } })
  expect((await delivered()).revokedSessionIds).toContain(endedSession!.id)
  const cooling = await f.deviceCall(machine, `/v1/projects/${f.project.id}/vars/RESTORE_MARKER`, { env: "dev", plain: "cooling" }, undefined, undefined, "PUT")
  expect(cooling.status).toBe(403)
  // What a restore to before both leaves: the object's account security as
  // it was, every directory delivery record unchanged, and the restore's
  // intent restarting, recorded by the operator as the script records it.
  await f.sql(f.work, "DELETE FROM account_security WHERE account=?", f.alex.account)
  for (const row of before) await f.sql(f.work, "INSERT INTO account_security(account,state) VALUES (?,?)", row.account, row.state)
  const now = Date.now(), fields = { id: `vri_${"a".repeat(32)}`, tenant: f.work.id, source: "pitr" as const, target: new Date(now - 3_600_000).toISOString(), actor: "operator:test", createdAt: now }
  await f.db.prepare("INSERT INTO vault_restore_intents(id,tenant,source,target,actor,intent_hash,created_at,expires_at,state,bookmark,undo_bookmark) VALUES (?,?,?,?,?,?,?,?,'restarting','bm','bm-undo')")
    .bind(fields.id, fields.tenant, fields.source, fields.target, fields.actor, await restoreIntentDigest(fields), now, now + 3_600_000).run()
  await f.cron()
  expect(await f.db.prepare("SELECT state FROM vault_restore_intents WHERE id=?").bind(fields.id).first()).toEqual({ state: "done" })
  // OPERATIONS.md, Restoring a workspace: the check owners stay frozen on.
  const undelivered = `SELECT (SELECT COUNT(*) FROM account_events e WHERE e.action IN ('account.signout','account.security','account.recovery_keep') AND EXISTS (SELECT 1 FROM json_each(e.targets) WHERE value='tn_<id>') AND NOT EXISTS (SELECT 1 FROM json_each(e.mirrored_to) WHERE value='tn_<id>')) + (SELECT COUNT(*) FROM account_security_transitions t WHERE EXISTS (SELECT 1 FROM json_each(t.targets) WHERE json_extract(value,'$.workspace')='tn_<id>') AND CASE t.state WHEN 'pending' THEN NOT EXISTS (SELECT 1 FROM json_each(t.acknowledged) WHERE json_extract(value,'$.workspace')='tn_<id>' AND json_extract(value,'$.reservedEpoch')=t.reserved_epoch) ELSE NOT EXISTS (SELECT 1 FROM json_each(t.commit_delivery) WHERE value='tn_<id>') END) AS undelivered`
  expect(await f.db.prepare(undelivered.replaceAll("tn_<id>", f.work.id)).first()).toEqual({ undelivered: 0 })
  expect(await delivered()).toMatchObject({ installedEpoch: account!.security_epoch, restriction: { reason: account!.restricted_reason, until: account!.restricted_until } })
  expect((await delivered()).revokedSessionIds).toContain(endedSession!.id)
  await refusal(await plain("after"), 403, await cooling.json())
})
