// Backup exports (areas/backups.ts). A person in the browser reads the
// recipients, registers or removes one with a passkey, and downloads an
// export as the age file itself. A machine reads the same status and asks
// for an export to a recipient by id; it receives the ciphertext in base64
// with its SHA-256, never a value.
import { z } from "zod"
import { StepUpAssertionProofSchema } from "@mehen/protocol/step-up-proof"
import { BACKUP_SHA256_HEADER, BackupRecipientAddSchema, type BackupStatus, backupCiphertextBase64, backupExportFileName, backupRecipientAddAction } from "@mehen/protocol"
import { assertSameOrigin } from "../directory/session.ts"
import { requireWorkspaceStepUp } from "../directory/workspace-stepup.ts"
import { json, parseJson, readBody } from "../http.ts"
import type { Route } from "../router.ts"
import type { BackupExportResult } from "../vault/areas/backups.ts"
import { type Handler, deviceRequest, workspaceCall } from "./context.ts"
import type { WorkspaceHandler } from "./workspace-prefix.ts"

const ExportRequest = z.strictObject({ recipient: z.string().min(1).max(128) })
const NO_STORE = { "cache-control": "no-store" }

export const workspaceBackupRoutes: Route<WorkspaceHandler>[] = [
  { method: "GET", path: "/backup/recipients", handler: async (rc, ws) => json(await workspaceCall(rc, ws, "backup.status"), 200, NO_STORE) },
  {
    method: "POST", path: "/backup/recipients", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp, ...input } = parseJson(BackupRecipientAddSchema.extend({ stepUp: StepUpAssertionProofSchema }), await readBody(rc.request))
      const action = await backupRecipientAddAction(input)
      return json(await workspaceCall(rc, ws, "backup.recipient_add", input, await requireWorkspaceStepUp(rc, ws, action, stepUp)), 201)
    },
  },
  {
    method: "POST", path: "/backup/recipients/:id/remove", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const { stepUp } = parseJson(z.strictObject({ stepUp: StepUpAssertionProofSchema }), await readBody(rc.request))
      const id = rc.params.id as string
      return json(await workspaceCall(rc, ws, "backup.recipient_remove", { id }, await requireWorkspaceStepUp(rc, ws, { type: "backup.recipient_remove", id }, stepUp)))
    },
  },
  {
    // The file itself, for the browser to save: the age bytes, named as
    // `mehen backup export` names them.
    method: "POST", path: "/backup/exports", handler: async (rc, ws) => {
      assertSameOrigin(rc.request, rc.env)
      const input = parseJson(ExportRequest, await readBody(rc.request))
      const result = await workspaceCall(rc, ws, "backup.export", input) as BackupExportResult
      const meta = result.export
      return new Response(result.ciphertext, { status: 200, headers: { ...NO_STORE, "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${backupExportFileName(meta)}"`, [BACKUP_SHA256_HEADER]: meta.ciphertext.sha256 } })
    },
  },
]

export const backupRoutes: Route<Handler>[] = [
  {
    method: "GET", path: "/v1/backup/recipients", handler: async (rc) => {
      const status = await (await deviceRequest(rc)).call("backup.status", {}) as BackupStatus
      return json({ recipients: status.recipients }, 200, NO_STORE)
    },
  },
  { method: "GET", path: "/v1/backup/status", handler: async (rc) => json(await (await deviceRequest(rc)).call("backup.status", {}), 200, NO_STORE) },
  {
    method: "POST", path: "/v1/backup/exports", handler: async (rc) => {
      const device = await deviceRequest(rc)
      const result = await device.call("backup.export", parseJson(ExportRequest, device.body)) as BackupExportResult
      return json({ export: result.export, ciphertext: backupCiphertextBase64(result.ciphertext) }, 200, { ...NO_STORE, [BACKUP_SHA256_HEADER]: result.export.ciphertext.sha256 })
    },
  },
]
