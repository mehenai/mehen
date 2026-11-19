// A workspace's audit log, from its filtered reader (GET /api/w/:ws/audit):
// each row as the vault's own audit sentence (ui/wording.ts), its time, and folded beneath it the exact stored
// action, target, detail, prev and hash, so a reader can check each row they
// were shown. Visibility chooses which rows come back, never their bytes;
// a private credential's rows are already minimal for every reader, its
// owner included. Only owners and admins can verify the whole chain.

import { PrivateEventSchema, type WorkspaceAuditEvent, type WorkspaceAuditPage } from "@mehen/protocol/workspace"
import { cardText, emptyState, kv, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import { type AuditActorContext, type AuditLine, auditLine } from "../wording.ts"
import type { Viewer } from "../workspace-rights.ts"

export type { WorkspaceAuditPage }

export const FILTERED_VIEW_WORDS = "Filtered view: only owners and admins can verify the whole chain."

// The pages a sentence may link to, under this workspace; any other link
// the shared sentences carry (an unprefixed place) is left out.
const LINKED = /^\/(items|a|i|c|projects)\//

function sentence(line: AuditLine, ws: string): Html {
  const pieces = line.pieces.map((p) => (p.as === "code" ? html`<code>${cardText(p.text)}</code>` : p.as === "name" ? html`<b>${cardText(p.text)}</b>` : p.as === "danger" ? html`<span class="refused">${cardText(p.text)}</span>` : p.as === "ok" ? html`<span class="ok">${cardText(p.text)}</span>` : cardText(p.text)))
  const link = line.link !== null && LINKED.test(line.link.href) ? html` <a class="small" href="${workspaceHref(ws, line.link.href)}">${line.link.label}</a>` : ""
  return html`${cardText(line.actor)}${pieces}${link}`
}

// The row's own private-event slug names it in the sentence, never its id.
function minimalSlug(event: WorkspaceAuditEvent): string | null {
  try {
    const parsed = PrivateEventSchema.safeParse(JSON.parse(event.detail))
    return parsed.success ? parsed.data.slug : null
  } catch {
    return null
  }
}

function eventRow(event: WorkspaceAuditEvent, words: AuditActorContext, ws: string): Html {
  const slug = minimalSlug(event)
  const minimal = slug !== null
  const line = auditLine({ actor: event.actor, action: event.action, target: minimal ? slug : event.target, detail: event.detail }, words)
  return html`<li class="audit-row" data-event="${String(event.seq)}"${minimal ? html` data-minimal="1"` : ""}>
    <p class="audit-sentence">${sentence(line, ws)}${minimal ? html` ${pill("private, minimal", "muted", false)}` : ""}</p>
    <p class="small muted">${timeTag(event.at)}</p>
    <details class="fold"><summary>${icon("chevronRight")}<span>Stored event ${String(event.seq)}</span></summary><dl class="kv small">
      <dt>Action</dt><dd><code>${cardText(event.action)}</code></dd>
      <dt>Actor</dt><dd><code>${cardText(event.actor)}</code></dd>
      <dt>Target</dt><dd><code>${cardText(event.target ?? "none")}</code></dd>
      <dt>Detail</dt><dd><code>${cardText(event.detail)}</code></dd>
      <dt>Prev</dt><dd><code class="hash">${event.prev}</code></dd>
      <dt>Hash</dt><dd><code class="hash">${event.hash}</code></dd>
    </dl></details>
  </li>`
}

// The page's lead: the chain's state as a pill and one sentence, or the
// filtered view's words.
function chainLine(page: WorkspaceAuditPage): Html {
  if (page.filtered) return html`<span data-region="filtered">${FILTERED_VIEW_WORDS}</span>`
  return html`<span data-region="chain">${page.verified ? html`${pill("Chain verified", "ok")} Every stored event links to the one before it.` : html`${pill("Chain not verified", "danger")} The stored events do not link up; tell the other owners.`}</span>`
}

// The chain's newest stored event, for checking against a copy: folded.
function chainHead(page: WorkspaceAuditPage): Html {
  if (page.filtered || page.head === null) return html``
  return html`<details class="fold" data-region="chain-head"><summary>${icon("chevronRight")}<span>Newest event in the chain</span></summary>${kv([["Event", String(page.head.seq)], ["Hash", html`<code class="hash">${page.head.hash}</code>`]], "small")}</details>`
}

export type AuditPageData = { viewer: Viewer; page: WorkspaceAuditPage; names?: { members?: ReadonlyMap<string, string>; devices?: ReadonlyMap<string, string> }; item?: string | null }

export function workspaceAuditPage(shell: WorkspaceShell, data: AuditPageData): PageInput {
  const words: AuditActorContext = { self: data.viewer.member, members: data.names?.members ?? new Map(), devices: data.names?.devices ?? new Map() }
  const ws = shell.identity.workspace.slug
  const item = data.item ?? null
  const older = data.page.next === null ? null : `/audit?${new URLSearchParams({ cursor: data.page.next, ...(item !== null ? { item } : {}) }).toString()}`
  return {
    title: "Activity",
    viewer: null,
    workspace: shell,
    current: "audit",
    boot: { page: "ws-audit" },
    body: html`${pageHead({ title: html`Activity${item !== null ? html` <code>${cardText(item)}</code>` : ""}`, lead: chainLine(data.page) })}
      ${chainHead(data.page)}
      <p class="small muted">Events about a private credential keep only who, when, which credential and the outcome, for every reader.</p>
      <section class="card">${data.page.events.length ? html`<ol class="audit-list">${data.page.events.map((e) => eventRow(e, words, ws))}</ol>` : emptyState("list", "Nothing yet", "Events appear here as people and machines act in this workspace.")}</section>
      ${older !== null ? html`<p><a class="btn secondary" href="${workspaceHref(ws, older)}">Older events</a></p>` : ""}`,
  }
}
