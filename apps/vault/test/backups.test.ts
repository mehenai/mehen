// Backup exports (areas/backups.ts) through their operations, under the
// workers pool: who may register, remove and export, the day's wait, the
// notices, what a bundle holds and leaves out, and what is recorded.
import { describe, expect, it } from "vitest"
import { Decrypter, generateX25519Identity, identityToRecipient } from "age-encryption"
import { BACKUP_EXCLUSION_REASONS, BACKUP_EXPORT_LIMITS, BACKUP_HIDDEN_ITEM, BACKUP_FORMAT, BACKUP_RECIPIENT_DELAY_MS, type BackupBundle, BackupBundleSchema, type BackupRecipientView, type BackupStatus, ageRecipientFingerprint, backupRecipientAddAction, createProof, sha256Hex, type WorkspaceNoticePayload } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { type BackupExportResult, backupsArea, workspaceBackupOps } from "../src/vault/areas/backups.ts"
import { setSetting, updateRestriction, installSecurity, type WorkspaceInvocationContext, type WorkspaceRuntimePrincipal } from "../src/vault/areas/workspace-runtime.ts"
import { noticeRows } from "../src/ui/pages/needs-you.ts"
import { auditLine } from "../src/ui/wording.ts"
import { noticesFor } from "../src/vault/areas/workspace-runtime.ts"
import { editAccessFixture, workspaceInvoke, accountAuth } from "./access-test-support.ts"
import { credentialsFixture, deviceInvocation, inAccess, memberInvocation, memberPrincipal, seedCredential, seedOAuthConnection } from "./credentials-test-support.ts"

const DAY = BACKUP_RECIPIENT_DELAY_MS
const SECRET = "test-secret-never-returned"

type Op = keyof typeof workspaceBackupOps
function at(ctx: VaultContext, ms: number): VaultContext {
  return Object.assign(Object.create(ctx) as VaultContext, { now: () => ms })
}
async function call<T>(ctx: VaultContext, op: Op, input: unknown, invocation: WorkspaceInvocationContext): Promise<T> {
  const auth = invocation.auth
  const principal: WorkspaceRuntimePrincipal = auth.kind === "device" ? { kind: "device", deviceId: JSON.parse(atob(auth.proof.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))).dev } : memberPrincipal(ctx, (auth as { account: string }).account.slice(4))
  return await workspaceBackupOps[op].handler(ctx, principal, input, invocation) as T
}
async function refused(promise: Promise<unknown>): Promise<{ error: string; message: string; retryAfter?: number }> {
  try { await promise } catch (error) { if (error instanceof VaultError) return error.toJSON() as { error: string; message: string }; throw error }
  throw new Error("accepted")
}
async function add(ctx: VaultContext, recipient: string, role = "owner", label = "Paper in the safe"): Promise<BackupRecipientView> {
  return call(ctx, "backup.recipient_add", { recipient, label }, memberInvocation(ctx, role, await backupRecipientAddAction({ recipient, label })))
}
function remove(ctx: VaultContext, id: string, role = "owner"): Promise<{ id: string; removed: true }> {
  return call(ctx, "backup.recipient_remove", { id }, memberInvocation(ctx, role, { type: "backup.recipient_remove", id }))
}
function exportTo(ctx: VaultContext, id: string, invocation: WorkspaceInvocationContext = memberInvocation(ctx)): Promise<BackupExportResult> {
  return call(ctx, "backup.export", { recipient: id }, invocation)
}
function status(ctx: VaultContext, invocation: WorkspaceInvocationContext = memberInvocation(ctx)): Promise<BackupStatus> {
  return call(ctx, "backup.status", {}, invocation)
}
async function open(identity: string, ciphertext: Uint8Array): Promise<BackupBundle> {
  const decrypter = new Decrypter()
  decrypter.addIdentity(identity)
  return BackupBundleSchema.parse(JSON.parse(await decrypter.decrypt(ciphertext, "text")))
}
function notices(ctx: VaultContext): { account: string; payload: WorkspaceNoticePayload }[] {
  return ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox ORDER BY account").toArray().map((r) => ({ account: r.account, payload: JSON.parse(r.payload) as WorkspaceNoticePayload })).filter((n) => n.payload.kind === "backup_recipient")
}
function auditText(ctx: VaultContext): string {
  return JSON.stringify(ctx.sql.exec("SELECT * FROM audit").toArray())
}
async function keyPair(): Promise<{ identity: string; recipient: string }> {
  const identity = await generateX25519Identity()
  return { identity, recipient: await identityToRecipient(identity) }
}
// An owner's recipient, a day old.
async function activeRecipient(ctx: VaultContext): Promise<{ identity: string; recipient: string; id: string; later: VaultContext }> {
  const key = await keyPair()
  const view = await add(ctx, key.recipient)
  return { ...key, id: view.id, later: at(ctx, ctx.now() + DAY) }
}

describe("backup recipients", () => {
  it("registers with a passkey over the exact recipient, label and scope, owners only, and waits a day", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { recipient } = await keyPair()
      expect(await refused(call(ctx, "backup.recipient_add", { recipient, label: "Safe" }, memberInvocation(ctx)))).toMatchObject({ error: "forbidden", message: expect.stringContaining("passkey") })
      const signedOther = await backupRecipientAddAction({ recipient, label: "Other" })
      expect(await refused(call(ctx, "backup.recipient_add", { recipient, label: "Safe" }, memberInvocation(ctx, "owner", signedOther)))).toMatchObject({ error: "forbidden" })
      for (const role of ["admin", "member", "guest"]) expect(await refused(add(ctx, recipient, role)), role).toMatchObject({ error: "forbidden" })
      expect(await refused(add(ctx, `age1pq1${"q".repeat(100)}`))).toMatchObject({ error: "bad_request" })

      const view = await add(ctx, recipient, "owner", "Safe")
      expect(view).toMatchObject({ recipient, label: "Safe", status: "pending", mine: true, fingerprint: ageRecipientFingerprint(recipient), registrant: { member: "mem_owner", name: "owner" }, lastExport: null })
      expect(Date.parse(view.activeAt) - Date.parse(view.registeredAt)).toBe(DAY)
      expect(view.id).toMatch(/^bkr_/)
      expect(await refused(add(ctx, recipient))).toMatchObject({ error: "conflict", message: "This recipient is already registered." })
      expect(auditText(ctx)).toContain("\"action\":\"backup.recipient_add\"")
      // Owners, admins and the registrant are told; a member and a guest are not.
      expect(notices(ctx).map((n) => n.account)).toEqual(["acc_admin", "acc_owner"])
      expect(notices(ctx)[0]!.payload).toMatchObject({ kind: "backup_recipient", member: "mem_owner", change: "added", recipient: { id: view.id, label: "Safe" }, by: "mem_owner" })
      const [notice] = noticesFor(ctx, memberPrincipal(ctx, "admin")).filter((n) => n.payload.kind === "backup_recipient")
      expect(notice!.url).toBe("https://vault.test/w/work/settings")
      expect(noticeRows([notice!], "https://vault.test", false).toString()).toContain(`A backup key was added: Safe (<code>${ageRecipientFingerprint(recipient)}</code>), registered by owner`)
    })
  })

  it("is refused to add while the owner is restricted or mid security change, and allowed to remove then", async () => {
    for (const standing of ["restricted", "pending"] as const) {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        const first = await add(ctx, (await keyPair()).recipient)
        if (standing === "restricted") updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_recovery" })
        else installSecurity(ctx, "acc_owner", 0, { transitionId: "ast_x", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: null })
        expect(await refused(add(ctx, (await keyPair()).recipient)), standing).toMatchObject(standing === "restricted" ? { error: "forbidden", message: expect.stringContaining("Your sign-in was recovered.") } : { error: "account_pending" })
        if (standing === "restricted") expect(await remove(ctx, first.id)).toEqual({ id: first.id, removed: true })
      })
    }
  })

  it("activates after exactly a day: export refused at 23:59, allowed at 24:00; the alarm tells everyone", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai")
      const t0 = ctx.now()
      const key = await keyPair()
      const view = await add(at(ctx, t0), key.recipient)
      expect(await refused(exportTo(at(ctx, t0 + DAY - 60_000), view.id))).toMatchObject({ error: "conflict", message: expect.stringContaining("becomes active") })
      expect((await status(at(ctx, t0 + DAY - 60_000))).recipients[0]).toMatchObject({ status: "pending", rights: { export: false, remove: true } })
      await backupsArea.alarm!(at(ctx, t0 + DAY - 60_000), `activate:${view.id}`)
      expect(notices(ctx).filter((n) => n.payload.kind === "backup_recipient" && n.payload.change === "active")).toEqual([])
      expect(ctx.sql.exec("SELECT key FROM schedule WHERE area='backups'").toArray()).toEqual([{ key: `activate:${view.id}` }])
      await backupsArea.alarm!(at(ctx, t0 + DAY), `activate:${view.id}`)
      expect(notices(ctx).filter((n) => n.payload.kind === "backup_recipient" && n.payload.change === "active").map((n) => n.account)).toEqual(["acc_admin", "acc_owner"])
      expect(auditText(ctx)).toContain("\"action\":\"backup.recipient_active\"")
      expect((await status(at(ctx, t0 + DAY))).recipients[0]).toMatchObject({ status: "active", rights: { export: true, remove: true } })
      const result = await exportTo(at(ctx, t0 + DAY), view.id)
      expect((await open(key.identity, result.ciphertext)).items.map((i) => i.slug)).toEqual(["openai"])
    })
  })

  it("is removed by its registrant or any other owner, never by an admin who did not register it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const view = await add(ctx, (await keyPair()).recipient)
      expect(await refused(remove(ctx, view.id, "admin"))).toMatchObject({ error: "forbidden" })
      expect(await refused(remove(ctx, view.id, "member"))).toMatchObject({ error: "forbidden" })
      expect(await refused(call(ctx, "backup.recipient_remove", { id: view.id }, memberInvocation(ctx)))).toMatchObject({ error: "forbidden", message: expect.stringContaining("passkey") })
      ctx.sql.exec("UPDATE members SET role='owner' WHERE id='mem_admin'")
      expect(await remove(ctx, view.id, "admin")).toEqual({ id: view.id, removed: true })
      expect(await refused(remove(ctx, view.id))).toMatchObject({ error: "not_found" })
      expect(notices(ctx).filter((n) => n.payload.kind === "backup_recipient" && n.payload.change === "removed")[0]!.payload).toMatchObject({ by: "mem_admin", member: "mem_owner" })
      expect((await status(ctx)).recipients).toEqual([])
      expect(ctx.sql.exec("SELECT key FROM schedule WHERE area='backups'").toArray()).toEqual([])
      // A registrant demoted since may still remove their own.
      const own = await add(ctx, (await keyPair()).recipient)
      ctx.sql.exec("UPDATE members SET role='member' WHERE id='mem_owner'")
      expect(await remove(ctx, own.id)).toEqual({ id: own.id, removed: true })
    })
  })

  it("every backup operation is not_found in a platform-managed workspace", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { recipient } = await keyPair()
      const view = await add(ctx, recipient)
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      for (const attempt of [status(ctx), add(ctx, (await keyPair()).recipient), remove(ctx, view.id), exportTo(at(ctx, ctx.now() + DAY), view.id)]) expect(await refused(attempt)).toMatchObject({ error: "not_found", message: "No such operation." })
    })
  })
})

describe("backup exports", () => {
  it("decrypt to exactly the owner's scope: workspace, project and own private credentials; never another member's; four-eyes and OAuth connection values listed apart", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const workspace = await seedCredential(ctx, "openai")
      await seedCredential(ctx, "billing-db", { kind: "project", project: "prj_a" })
      await seedCredential(ctx, "owner-own", { kind: "member", member: "mem_owner" })
      const adminOwn = await seedCredential(ctx, "admin-own", { kind: "member", member: "mem_admin" })
      const guarded = await seedCredential(ctx, "stripe-live", { kind: "project", project: "prj_a" })
      const connection = await seedOAuthConnection(ctx)
      editAccessFixture(ctx, (s) => {
        const prjA = s.projects.find((p) => p.id === "prj_a")!
        prjA.environments.find((e) => e.name === "dev")!.references = [{ variable: "OPENAI_API_KEY", field: "key", item: workspace.id, home: { kind: "workspace" }, revision: 1 }, { variable: "ADMIN_KEY", field: "key", item: adminOwn.id, home: { kind: "member", member: "mem_admin" }, revision: 1 }]
        prjA.environments.find((e) => e.name === "dev")!.plainVariables = { LOG_LEVEL: "info" }
        prjA.environments.find((e) => e.name === "prod")!.references = [{ variable: "STRIPE_KEY", field: "key", item: guarded.id, home: { kind: "project", project: "prj_a" }, revision: 1 }]
      })
      const { identity, id, later } = await activeRecipient(ctx)
      const result = await exportTo(later, id)
      expect(result.export).toMatchObject({ workspace: { slug: "work" }, recipient: { id }, items: 5, excluded: 2, ciphertext: { bytes: result.ciphertext.length, sha256: await sha256Hex(result.ciphertext) } })
      const bundle = await open(identity, result.ciphertext)
      expect(bundle).toMatchObject({ format: BACKUP_FORMAT, id: result.export.id, workspace: { id: ctx.tenant, slug: "work", name: "Work" }, registrant: { member: "mem_owner" }, recipient: { id, fingerprint: result.export.recipient.fingerprint } })
      expect(bundle.items.map((i) => i.slug).sort()).toEqual(["billing-db", "gmail-test", "google-client", "openai", "owner-own"])
      expect(Object.fromEntries(bundle.items.map((i) => [i.slug, i.secretFields]))).toEqual({ "billing-db": { key: SECRET }, "gmail-test": {}, "google-client": { client_secret: "test-client-secret" }, openai: { key: SECRET }, "owner-own": { key: SECRET } })
      expect(bundle.items.find((i) => i.slug === "gmail-test")).toMatchObject({ id: connection.id, kind: "oauth-connection" })
      expect(bundle.excluded).toEqual([{ slug: "gmail-test", reason: BACKUP_EXCLUSION_REASONS.oauthConnection }, { slug: "stripe-live", reason: BACKUP_EXCLUSION_REASONS.fourEyes }])
      const text = JSON.stringify(bundle)
      expect(text).not.toContain("admin-own")
      expect(text).not.toContain(adminOwn.id)
      expect(text).not.toContain("test-access")
      expect(text).not.toContain("test-refresh")
      const dev = bundle.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "dev")!
      expect(dev.vars).toEqual({ LOG_LEVEL: { plain: "info" }, OPENAI_API_KEY: { item: "openai", field: "key" }, ADMIN_KEY: { item: BACKUP_HIDDEN_ITEM, field: "key", notExported: true } })
      expect(bundle.projects.find((p) => p.id === "prj_a")!.environments.find((e) => e.name === "prod")!.vars).toEqual({ STRIPE_KEY: { item: "stripe-live", field: "key", notExported: true } })
      expect(bundle.auditHead).toMatchObject({ seq: expect.any(Number), hash: expect.any(String) })
    })
  })

  it("only an owner exports, only to their own recipient, from the browser or their own machine; never a workload, a team machine or another member's machine", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai")
      const { id, later } = await activeRecipient(ctx)
      for (const role of ["admin", "member", "guest"]) expect(await refused(exportTo(later, id, memberInvocation(ctx, role))), role).toMatchObject({ error: "forbidden" })
      for (const device of ["dev_admin", "dev_member", "dev_service"]) expect(await refused(exportTo(later, id, await deviceInvocation(ctx, device))), device).toMatchObject({ error: "forbidden" })
      const now = ctx.now()
      ctx.sql.exec("INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES ('wkl_task','dev_owner','task','{}','thumb-task','{}',?,?,?)", now, now + 2 * DAY, now + 2 * DAY)
      const proof = await createProof({ deviceId: "dev_owner", workloadId: "wkl_task", sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/backup/exports" }, { tenant: ctx.tenant })
      expect(await refused(exportTo(later, id, { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "device", proof, method: "POST", url: "https://vault.test/v1/backup/exports", bodyHash: "" } }))).toMatchObject({ error: "forbidden" })
      const fromMachine = await exportTo(later, id, await deviceInvocation(ctx, "dev_owner"))
      expect(fromMachine.export.items).toBe(1)
      expect(ctx.sql.exec("SELECT actor FROM backup_exports").toArray()).toEqual([{ actor: "device:dev_owner" }])
    })
  })

  it("re-checks the registrant's live standing: restricted, removed or demoted is refused, from the browser and the machine", async () => {
    for (const change of ["restricted", "removed", "demoted", "suspended"] as const) {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (ctx) => {
        await seedCredential(ctx, "openai")
        const { id, later } = await activeRecipient(ctx)
        if (change === "restricted") updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + 2 * DAY, notice: "ntc_recovery" })
        if (change === "removed") ctx.sql.exec("UPDATE members SET status='removed' WHERE id='mem_owner'")
        if (change === "suspended") ctx.sql.exec("UPDATE members SET status='suspended' WHERE id='mem_owner'")
        if (change === "demoted") ctx.sql.exec("UPDATE members SET role='admin' WHERE id='mem_owner'")
        const expected = { restricted: { error: "forbidden", message: expect.stringContaining("Your sign-in was recovered.") }, removed: { error: "owner_inactive" }, suspended: { error: "owner_inactive" }, demoted: { error: "forbidden" } }[change]
        expect(await refused(exportTo(later, id, await deviceInvocation(ctx, "dev_owner"))), change).toMatchObject(expected)
        // A removed member has no session to call with.
        if (change !== "removed") expect(await refused(exportTo(later, id)), change).toMatchObject(expected)
        expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM backup_exports").one().n, change).toBe(0)
      })
    }
  })

  it("records an exposure per exported item version and an audit entry with no value; one export per recipient per ten minutes", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const a = await seedCredential(ctx, "openai")
      const b = await seedCredential(ctx, "owner-own", { kind: "member", member: "mem_owner" })
      const { id, later } = await activeRecipient(ctx)
      const first = await exportTo(later, id, await deviceInvocation(ctx, "dev_owner"))
      const exposures = ctx.sql.exec("SELECT event,item,version,member,device,source FROM exposures WHERE source='exported' ORDER BY item").toArray()
      expect(exposures).toEqual([a, b].sort((x, y) => x.id < y.id ? -1 : 1).map((item) => ({ event: `export:${first.export.id}`, item: item.id, version: item.version, member: "mem_owner", device: "dev_owner", source: "exported" })))
      const audit = ctx.sql.exec<{ actor: string; action: string; target: string; detail: string }>("SELECT actor,action,target,detail FROM audit WHERE action='backup.export'").toArray()
      expect(audit).toHaveLength(1)
      expect(audit[0]).toMatchObject({ actor: "device:dev_owner", target: first.export.id })
      expect(JSON.parse(audit[0]!.detail)).toMatchObject({ recipient: id, items: 2, sha256: first.export.ciphertext.sha256 })
      expect(auditText(ctx)).not.toContain(SECRET)
      expect(JSON.stringify(ctx.sql.exec("SELECT * FROM backup_exports").toArray())).not.toContain(SECRET)
      expect(auditLine({ ...audit[0]!, target: audit[0]!.target }, { self: null, devices: new Map() })).toEqual({ actor: expect.anything(), pieces: [{ text: " exported 2 credentials, encrypted to the backup key " }, { text: JSON.parse(audit[0]!.detail).fingerprint, as: "code" }], link: { href: "/settings", label: "Open settings" } })

      const soon = at(ctx, later.now() + BACKUP_EXPORT_LIMITS.intervalMs - 1_000)
      expect(await refused(exportTo(soon, id))).toMatchObject({ error: "rate_limited", retryAfter: 1 })
      expect((await exportTo(at(ctx, later.now() + BACKUP_EXPORT_LIMITS.intervalMs), id)).export.items).toBe(2)
    })
  })

  it("holds one export per recipient per ten minutes when two arrive at once: the second is refused before it opens anything, and an export finished meanwhile is checked again at the final point", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai")
      const { id, later } = await activeRecipient(ctx)
      const machine = await deviceInvocation(ctx, "dev_owner")
      const [a, b] = await Promise.allSettled([exportTo(later, id), exportTo(later, id, machine)])
      expect(a.status).toBe("fulfilled")
      expect(b.status).toBe("rejected")
      expect(b.status === "rejected" && b.reason instanceof VaultError ? b.reason.toJSON() : null).toMatchObject({ error: "rate_limited", message: "An export to this backup recipient is already being made.", retryAfter: BACKUP_EXPORT_LIMITS.intervalMs / 1000 })
      expect(ctx.sql.exec("SELECT id FROM backup_exports").toArray()).toHaveLength(1)

      const next = at(ctx, later.now() + BACKUP_EXPORT_LIMITS.intervalMs)
      const racing = exportTo(next, id)
      ctx.sql.exec("INSERT INTO backup_exports(id,recipient,actor,items,projects,excluded,bytes,sha256,at) VALUES (?,?,?,?,?,?,?,?,?)", "bkx_elsewhere", id, "member:mem_owner", 1, 0, 0, 1, "0".repeat(64), next.now())
      expect(await refused(racing)).toMatchObject({ error: "rate_limited", message: "Another export to this backup recipient was made first; one every ten minutes." })
      expect(ctx.sql.exec("SELECT id FROM backup_exports").toArray()).toHaveLength(2)
      expect(ctx.sql.exec("SELECT event FROM exposures WHERE source='exported'").toArray()).toHaveLength(1)
      expect((await exportTo(at(ctx, next.now() + BACKUP_EXPORT_LIMITS.intervalMs), id)).export.items).toBe(1)
    })
  })

  it("status shows the last export and what changed since, only to the registrant; never to a guest or a workload", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai")
      const { id, later } = await activeRecipient(ctx)
      expect((await status(later)).recipients[0]).toMatchObject({ id, lastExport: null, changedSince: 1 })
      const result = await exportTo(later, id)
      const after = at(ctx, later.now() + 1_000)
      expect((await status(after)).recipients[0]).toMatchObject({ lastExport: { id: result.export.id, items: 1 }, changedSince: 0 })
      await seedCredential(after, "anthropic")
      expect((await status(at(ctx, later.now() + 2_000), await deviceInvocation(ctx, "dev_owner"))).recipients[0]).toMatchObject({ changedSince: 1, mine: true, rights: { export: true } })
      expect((await status(after, memberInvocation(ctx, "admin"))).recipients[0]).toMatchObject({ mine: false, lastExport: null, changedSince: null, rights: { export: false, remove: false } })
      expect(await status(after, memberInvocation(ctx, "admin"))).toMatchObject({ rights: { add: false } })
      expect(await refused(status(after, memberInvocation(ctx, "guest")))).toMatchObject({ error: "forbidden" })
    })
  })

  it("through the object's dispatch: ciphertext crosses RPC intact, a machine cannot register, and add is account only", async () => {
    const f = await credentialsFixture()
    const { identity, recipient } = await keyPair()
    const { id } = await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai")
      const view = await add(ctx, recipient)
      ctx.sql.exec("UPDATE backup_recipients SET registered_at=registered_at-?, active_at=active_at-? WHERE id=?", DAY, DAY, view.id)
      return view
    })
    const result = await workspaceInvoke(f.tenant, "backup.export", { recipient: id }, accountAuth())
    if (!result.ok) throw new Error(JSON.stringify(result.error))
    const value = result.value as BackupExportResult
    expect(value.ciphertext).toBeInstanceOf(Uint8Array)
    expect(await sha256Hex(value.ciphertext)).toBe(value.export.ciphertext.sha256)
    expect((await open(identity, value.ciphertext)).items.map((i) => i.slug)).toEqual(["openai"])
    const proof = await createProof({ deviceId: "dev_owner", sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/backup/recipients" }, { tenant: f.tenant })
    const fromDevice = await workspaceInvoke(f.tenant, "backup.recipient_add", { recipient, label: "x" }, { kind: "device", proof, method: "POST", url: "https://vault.test/v1/backup/recipients", bodyHash: "" })
    expect(fromDevice.ok).toBe(false)
  })
})
