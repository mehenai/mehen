// Needs you inside one workspace (/w/:ws/pending), a filter of the account
// inbox: the same rows, from this workspace's inbox (GET /api/w/:ws/inbox),
// headed with this workspace's own count. What waits in the account's
// other workspaces is a line the client fills from the account-wide read,
// linking to /needs-you; this page never counts another workspace itself.
// A review group's row leads to Review together (workspace-review.ts).

import type { WorkspaceInboxResponse } from "@mehen/protocol/inbox"
import { cardText, emptyState, pageHead } from "../components.ts"
import { html } from "../html.ts"
import { inboxRow, inboxRowOf } from "../inbox-row.ts"
import type { PageInput } from "../layout.ts"
import type { WorkspaceShell } from "../shell.ts"
import type { Viewer } from "../workspace-rights.ts"
import { groupNotice, noticeRows } from "./needs-you.ts"

export type PendingPageData = { viewer: Viewer; inbox: WorkspaceInboxResponse; now: number }

export function workspacePendingPage(shell: WorkspaceShell, data: PendingPageData): PageInput {
  const { inbox, now } = data
  const name = cardText(shell.identity.workspace.name)
  const n = inbox.items.length
  const answered = inbox.workspace.state === "ok"
  const count = answered && n > 0 ? html` <span class="pill accent">${inbox.workspace.truncated ? `${n}+` : String(n)} here</span>` : html``
  const lead = data.viewer.role === "guest" ? "Your own machines' asks in this workspace." : "What you may decide or stop in this workspace, and your own machines' asks, soonest first."
  const empty = emptyState("check", html`Nothing is waiting for you in ${name}`, html`Everything waiting in your other workspaces is under <a href="/needs-you">Needs you</a>.`)
  return {
    title: `Needs you in ${shell.identity.workspace.name}`,
    viewer: null,
    workspace: shell,
    current: "needs",
    boot: { page: "ws-pending" },
    body: html`${pageHead({ title: html`Needs you in ${name}${count}`, lead })}
      <p class="small" data-region="needs-elsewhere" hidden><a href="/needs-you" data-fill="needs-elsewhere"></a></p>
      <section class="card" data-region="needs-group" data-workspace="${shell.identity.workspace.id}" data-state="${inbox.workspace.state}">
        ${groupNotice(inbox.workspace, true)}
        <ul class="rows" data-region="pending">${inbox.items.map((item) => inboxRow(inboxRowOf(item, inbox.workspace), { now, showWorkspace: false }))}</ul>
        ${n === 0 && answered && !inbox.workspace.truncated ? empty : ""}
      </section>
      ${noticeRows(inbox.notices, shell.identity.origin, false)}`,
  }
}
