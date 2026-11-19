// Backup exports over HTTP: the person's /api/w/:ws/backup routes with a
// passkey to register and remove a recipient and the age file as the
// download, and the machine's /v1/backup routes, which answer only
// ciphertext in base64 with its SHA-256.
import { expect, it } from "vitest"
import { Decrypter, generateX25519Identity, identityToRecipient } from "age-encryption"
import { BACKUP_EXPORT_LIMITS, BACKUP_SHA256_HEADER, type BackupExportResponse, BackupExportResponseSchema, type BackupRecipientView, type BackupStatus, backupExportFileName, backupRecipientAddAction, sha256Hex } from "@mehen/protocol"
import { body, refusal, workJourney } from "./workspace-journey.ts"

async function opened(identity: string, ciphertext: Uint8Array): Promise<{ items: { slug: string }[] }> {
  const decrypter = new Decrypter()
  decrypter.addIdentity(identity)
  return JSON.parse(await decrypter.decrypt(ciphertext, "text"))
}

it("backup over HTTP: register with a passkey, wait a day, download from the browser, export from the machine, remove", async () => {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  await f.credential(f.alex, f.work, "backup-key", { kind: "workspace" })
  const identity = await generateX25519Identity()
  const recipient = await identityToRecipient(identity)
  const base = `/api/w/${f.work.slug}/backup`

  expect(await body<BackupStatus>(await f.request(`${base}/recipients`, f.alex))).toEqual({ recipients: [], rights: { add: true }, now: expect.any(String) })
  // The account-wide step-up does not sign a workspace's backup key, and no passkey refuses.
  expect((await f.request("/api/account/stepup/start", f.alex, { action: await backupRecipientAddAction({ recipient, label: "Safe" }) })).status).toBe(400)
  expect((await f.request(`${base}/recipients`, f.alex, { recipient, label: "Safe" })).status).toBe(400)
  const view = await body<BackupRecipientView>(await f.signed(`${base}/recipients`, f.alex, { recipient, label: "Safe" }, await backupRecipientAddAction({ recipient, label: "Safe" }), f.work.slug), 201)
  expect(view).toMatchObject({ recipient, label: "Safe", status: "pending" })
  await refusal(await f.request(`${base}/exports`, f.alex, { recipient: view.id }), 409, { error: "conflict", message: `This backup recipient becomes active at ${view.activeAt}, a day after it was registered.`, next: { say: "Wait until then; every owner and admin was told it was added and can remove it before." } })

  await f.sql(f.work, "UPDATE backup_recipients SET active_at=? WHERE id=?", Date.now() - 1, view.id)
  const download = await f.request(`${base}/exports`, f.alex, { recipient: view.id })
  expect(download.status).toBe(200)
  expect(download.headers.get("content-type")).toBe("application/octet-stream")
  expect(download.headers.get("cache-control")).toBe("no-store")
  const bytes = new Uint8Array(await download.arrayBuffer())
  expect(download.headers.get(BACKUP_SHA256_HEADER)).toBe(await sha256Hex(bytes))
  const [row] = await f.sql<{ id: string; at: number }>(f.work, "SELECT id,at FROM backup_exports")
  expect(download.headers.get("content-disposition")).toBe(`attachment; filename="${backupExportFileName({ id: row!.id, workspace: f.work, exportedAt: new Date(row!.at).toISOString() })}"`)
  expect((await opened(identity, bytes)).items.map((i) => i.slug)).toEqual(["backup-key"])

  const status = await body<BackupStatus>(await f.deviceCall(machine, "/v1/backup/status"))
  expect(status.recipients[0]).toMatchObject({ id: view.id, status: "active", mine: true, lastExport: { id: row!.id, items: 1 }, changedSince: 0, rights: { export: true, remove: false } })
  expect(await body(await f.deviceCall(machine, "/v1/backup/recipients"))).toEqual({ recipients: status.recipients })
  const limited = await f.deviceCall(machine, "/v1/backup/exports", { recipient: view.id })
  expect(limited.status).toBe(429)
  expect(await limited.json()).toMatchObject({ error: "rate_limited", retryAfter: expect.any(Number) })
  await f.sql(f.work, "UPDATE backup_exports SET at=at-?", BACKUP_EXPORT_LIMITS.intervalMs)
  const fromMachine = await f.deviceCall(machine, "/v1/backup/exports", { recipient: view.id })
  const answer: BackupExportResponse = BackupExportResponseSchema.parse(await body(fromMachine))
  const ciphertext = Uint8Array.from(atob(answer.ciphertext), (c) => c.charCodeAt(0))
  expect(fromMachine.headers.get(BACKUP_SHA256_HEADER)).toBe(answer.export.ciphertext.sha256)
  expect(await sha256Hex(ciphertext)).toBe(answer.export.ciphertext.sha256)
  expect((await opened(identity, ciphertext)).items.map((i) => i.slug)).toEqual(["backup-key"])
  expect(JSON.stringify(answer)).not.toContain("backup-key")

  await refusal(await f.deviceCall(machine, "/v1/backup/exports", { recipient: "bkr_missing123" }), 404, { error: "not_found", message: "No such backup recipient." })
  expect((await f.request(`${base}/recipients/${view.id}/remove`, f.alex, {})).status).toBe(400)
  expect(await body(await f.signed(`${base}/recipients/${view.id}/remove`, f.alex, {}, { type: "backup.recipient_remove", id: view.id }, f.work.slug))).toEqual({ id: view.id, removed: true })
  expect((await body<BackupStatus>(await f.request(`${base}/recipients`, f.alex))).recipients).toEqual([])
})
