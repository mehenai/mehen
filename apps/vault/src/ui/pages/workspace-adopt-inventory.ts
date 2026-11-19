// The adoption inventory (/w/<slug>/adopt): every name this person's
// adoptions touch, one row each, from their open batches, what their
// approved batches stored or mapped, and their machines' last plans. Which
// machines have it, its outcome or open batch with a link to its review
// page, and the item under the name where this person may read it. A
// result shows only where the vault gives one; never a value.

import type { AdoptionInventoryEntry, AdoptionInventoryRow, WorkspaceAdoptionInventory } from "@mehen/protocol/adopt"
import type { WorkspaceProject } from "@mehen/protocol/workspace"
import { ADOPTION_RESULT_WORDS } from "../client/pages/workspace-adopt-logic.ts"
import { cardText, emptyState, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, workspaceHref } from "../shell.ts"
import { joinWords } from "../wording.ts"
import { belongsToWords } from "../workspace-rights.ts"

const RESULT_TONES = { same: "ok", differs: "warn", unknown: "muted" } as const
// What an approved batch did with the name; mapped never says whether the
// values were the same.
const OUTCOME_WORDS = { created: "stored by batch", mapped: "uses the vault's value, by batch", replaced: "replaced the vault's value, by batch" } as const

function entryLine(entry: AdoptionInventoryEntry, ws: string): Html {
  const machine = cardText(entry.machine)
  if (entry.from === "staged") {
    const result = entry.compare !== null ? html` ${pill(ADOPTION_RESULT_WORDS[entry.compare], RESULT_TONES[entry.compare], false)}` : ""
    return html`<li>${machine}: waiting in batch <a href="${workspaceHref(ws, `/b/${encodeURIComponent(entry.adoption)}`)}"><code>${entry.adoption}</code></a>${result}</li>`
  }
  if (entry.from === "approved") return html`<li>${machine}: ${OUTCOME_WORDS[entry.outcome]} <code>${entry.adoption}</code></li>`
  const facts = [entry.include ? "ticked" : "left out", ...(entry.exists ? ["already in the vault"] : []), ...(entry.storeOnly ? ["store-only"] : [])]
  const backs = entry.uses.length > 0 ? html`, backs ${entry.uses.map((u, i) => html`${i === 0 ? "" : ", "}<code>${cardText(u.project)} / ${cardText(u.env)} / ${cardText(u.variable)}</code>`)}` : ""
  return html`<li>${cardText(`${entry.machine}'s plan`)}: ${facts.join(", ")}${backs}</li>`
}

function inventoryRow(row: AdoptionInventoryRow, ws: string, slugs: ReadonlyMap<string, string>): Html {
  const machines = [...new Set(row.entries.map((e) => e.machine))].sort()
  const stored = row.stored !== null
    ? html`<a href="${workspaceHref(ws, `/items/${encodeURIComponent(row.slug)}`)}">In the vault, version ${row.stored.version}</a> <span class="small muted">${belongsToWords(row.stored.home, slugs)}</span>`
    : html`<span class="muted">Nothing under this name that you can see.</span>`
  return html`<li class="inventory-row" data-slug="${row.slug}">
    <div class="inventory-head"><code class="slug-inline">${cardText(row.slug)}</code> ${stored}</div>
    <p class="small">On ${cardText(joinWords(machines))}.</p>
    <ul class="inventory-entries small">${row.entries.map((e) => entryLine(e, ws))}</ul>
  </li>`
}

export function workspaceAdoptInventoryPage(shell: WorkspaceShell, inventory: WorkspaceAdoptionInventory, projects: readonly WorkspaceProject[]): PageInput {
  const ws = shell.identity.workspace.slug
  const slugs = new Map(projects.map((p) => [p.id, p.slug]))
  const plans = inventory.indexes.length > 0
    ? html`<p class="small muted" data-region="indexes">${inventory.indexes.map((x, i) => html`${i === 0 ? "" : "; "}${cardText(x.machine)} sent its plan ${timeTag(x.indexedAt)}, kept until ${timeTag(x.expiresAt)}`)}.</p>`
    : ""
  return {
    title: "Adopted credentials",
    viewer: null,
    workspace: shell,
    current: "credentials",
    boot: { page: "ws-adopt-inventory" },
    body: html`${pageHead({ title: "Adopted credentials", lead: "Every name your machines' adoptions touch: the machines that have it, its open batch or what was decided, and the credential stored under it. No page shows a value." })}
      ${inventory.rows.length > 0
        ? html`<section class="card">${plans}<ul class="rows inventory-rows" data-region="inventory">${inventory.rows.map((r) => inventoryRow(r, ws, slugs))}</ul></section>`
        : html`<section class="card">${plans}${emptyState("key", "Nothing adopted yet", "Run mehen adopt on a machine to find the credentials it already holds; each batch then waits here for your passkey.")}</section>`}`,
  }
}
