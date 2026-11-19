// The browser side of /w/:ws/settings. Renaming and the short name are
// signed with a passkey for the exact new name and short name; Unfreeze is
// signed for workspace.unfreeze; Freeze needs only its confirm step. How
// often Mehen asks is signed for workspace.approvals with the level shown
// and the one chosen when it asks less, and sent unsigned when it asks
// more; the line above Save says which before anything is sent. A
// backup key is added with a passkey over the exact recipient, label and
// scope, and removed with one; an export downloads the age file once its
// SHA-256 matches what the vault said. Each
// change reloads (or moves to the new short name's address) so the page
// shows the vault's own state. A refusal is shown as the vault words it.

import { BACKUP_SHA256_HEADER, BackupRecipientAddSchema, backupRecipientAddAction, sha256Hex } from "@mehen/protocol/backup"
import { ApprovalDialSchema, approvalDialAsksLess, type WorkspaceRef, type WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { APPROVAL_DIAL_SAVE, APPROVAL_DIAL_SAVE_PASSKEY, approvalDialSignsWords } from "../../approval-dial-words.ts"
import { VaultFailure, workspaceApi, workspaceFile } from "../api.ts"
import { find, inputValue, must, withBusy } from "../dom.ts"
import type { ShellState } from "../shell-logic.ts"
import { workspaceStepUp } from "../step-up.ts"

async function signedUpdate(shell: ShellState, change: { change: "name"; name: string } | { change: "slug"; slug: string }): Promise<WorkspaceRef> {
  const now = shell.identity.workspace
  const action: WorkspaceStepUpAction = { type: "workspace.update", name: change.change === "name" ? change.name : now.name, slug: change.change === "slug" ? change.slug : now.slug }
  const stepUp = await workspaceStepUp(shell, action)
  return (await workspaceApi<{ workspace: WorkspaceRef }>(shell, "/settings", { ...change, stepUp })).workspace
}

function wireRename(shell: ShellState): void {
  const nameForm = find<HTMLFormElement>('[data-form="workspace-name"]')
  nameForm?.addEventListener("submit", (event) => {
    event.preventDefault()
    const name = inputValue('[data-input="workspace-name"]', nameForm).trim()
    if (name === "") {
      find<HTMLInputElement>('[data-input="workspace-name"]', nameForm)?.focus()
      return
    }
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', nameForm), "Waiting for your passkey...", async () => {
      await signedUpdate(shell, { change: "name", name })
      location.reload()
    })
  })
  const slugForm = find<HTMLFormElement>('[data-form="workspace-slug"]')
  slugForm?.addEventListener("submit", (event) => {
    event.preventDefault()
    const slug = inputValue('[data-input="workspace-slug"]', slugForm).trim().toLowerCase()
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', slugForm), "Waiting for your passkey...", async () => {
      const after = await signedUpdate(shell, { change: "slug", slug })
      location.assign(`/w/${encodeURIComponent(after.slug)}/settings`)
    })
  })
}

// Freeze shows its consequence first; the filled button sends it. Opened
// from the palette (#freeze), the confirm step is shown straight away.
function wireFreeze(shell: ShellState): void {
  const start = find<HTMLElement>('[data-region="freeze-start"]')
  const confirm = find<HTMLElement>('[data-region="freeze-confirm"]')
  if (!start || !confirm) return
  const send = must<HTMLButtonElement>('[data-action="workspace-freeze"]', confirm)
  const show = (open: boolean) => {
    start.hidden = open
    confirm.hidden = !open
    if (open) send.focus()
    else must<HTMLButtonElement>('[data-action="freeze-start"]', start).focus()
  }
  must<HTMLButtonElement>('[data-action="freeze-start"]', start).addEventListener("click", () => show(true))
  must<HTMLButtonElement>('[data-action="freeze-cancel"]', confirm).addEventListener("click", () => show(false))
  send.addEventListener("click", () => {
    void withBusy(send, "Freezing...", async () => {
      await workspaceApi(shell, "/freeze", {})
      location.reload()
    })
  })
  if (location.hash === "#freeze") show(true)
}

function wireUnfreeze(shell: ShellState): void {
  const button = find<HTMLButtonElement>('[data-action="workspace-unfreeze"]')
  button?.addEventListener("click", () => {
    void withBusy(button, "Waiting for your passkey...", async () => {
      const stepUp = await workspaceStepUp(shell, { type: "workspace.unfreeze" })
      await workspaceApi(shell, "/unfreeze", { stepUp })
      location.reload()
    })
  })
}

function wireApprovals(shell: ShellState): void {
  const card = find<HTMLElement>('[data-region="approvals"][data-level]')
  if (!card) return
  const shown = ApprovalDialSchema.safeParse(card.dataset.level)
  if (!shown.success) return
  const before = shown.data
  const save = must<HTMLButtonElement>('[data-action="approvals-save"]', card)
  const signs = must<HTMLElement>('[data-region="approvals-signs"]', card)
  const chosen = () => ApprovalDialSchema.safeParse(card.querySelector<HTMLInputElement>('[data-input="approvals-level"]:checked')?.value)
  const show = () => {
    const after = chosen()
    const changed = after.success && after.data !== before
    save.disabled = !changed
    signs.hidden = !changed
    const less = changed && approvalDialAsksLess(before, after.data)
    signs.textContent = changed ? approvalDialSignsWords(before, after.data, less) : ""
    save.textContent = less ? APPROVAL_DIAL_SAVE_PASSKEY : APPROVAL_DIAL_SAVE
  }
  for (const input of card.querySelectorAll<HTMLInputElement>('[data-input="approvals-level"]')) input.addEventListener("change", show)
  save.addEventListener("click", () => {
    const after = chosen()
    if (!after.success || after.data === before) return
    const change = { before, after: after.data }
    void withBusy(save, approvalDialAsksLess(before, after.data) ? "Waiting for your passkey..." : "Saving...", async () => {
      const stepUp = approvalDialAsksLess(before, after.data) ? await workspaceStepUp(shell, { type: "workspace.approvals", ...change }) : undefined
      await workspaceApi(shell, "/settings/approvals", stepUp ? { ...change, stepUp } : change)
      location.reload()
    })
  })
}

function wireBackups(shell: ShellState): void {
  const form = find<HTMLFormElement>('[data-form="backup-add"]')
  form?.addEventListener("submit", (event) => {
    event.preventDefault()
    const parsed = BackupRecipientAddSchema.safeParse({ recipient: inputValue('[data-input="backup-recipient"]', form).trim(), label: inputValue('[data-input="backup-label"]', form) })
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', form), "Waiting for your passkey...", async () => {
      if (!parsed.success) throw new VaultFailure(400, { error: "bad_request", message: "Give an age1... X25519 recipient and a label of up to 64 characters.", next: { say: "Nothing was signed." } })
      const stepUp = await workspaceStepUp(shell, await backupRecipientAddAction(parsed.data))
      await workspaceApi(shell, "/backup/recipients", { ...parsed.data, stepUp })
      location.reload()
    })
  })
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-action="backup-remove"]')) {
    const id = button.dataset.recipient ?? ""
    button.addEventListener("click", () => {
      void withBusy(button, "Waiting for your passkey...", async () => {
        const stepUp = await workspaceStepUp(shell, { type: "backup.recipient_remove", id })
        await workspaceApi(shell, `/backup/recipients/${encodeURIComponent(id)}/remove`, { stepUp })
        location.reload()
      })
    })
  }
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-action="backup-export"]')) {
    button.addEventListener("click", () => {
      void withBusy(button, "Encrypting the export...", async () => {
        const { bytes, headers } = await workspaceFile(shell, "/backup/exports", { recipient: button.dataset.recipient ?? "" })
        if (headers.get(BACKUP_SHA256_HEADER) !== await sha256Hex(bytes)) throw new VaultFailure(502, { error: "upstream_failed", message: "The export arrived damaged: its SHA-256 does not match.", next: { say: "Nothing was saved. Try again." } })
        const name = /filename="([^"]+)"/.exec(headers.get("content-disposition") ?? "")?.[1] ?? "mehen-backup.age"
        const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }))
        const link = document.createElement("a")
        link.href = url
        link.download = name
        link.click()
        setTimeout(() => URL.revokeObjectURL(url), 60_000)
      })
    })
  }
}

export function initWorkspaceSettings(_boot: unknown, shell: ShellState | null): void {
  if (shell === null) return
  wireRename(shell)
  wireFreeze(shell)
  wireUnfreeze(shell)
  wireApprovals(shell)
  wireBackups(shell)
}
