// mehen adopt inventory: this machine's side of the inventory page, from
// the plan file, the saved state and the device answer for each batch this
// machine submitted to. It reads nothing only an account may see, so a
// machine learns no name it could not already see, and never a value, a
// fingerprint, a tag or how a compare row compared.

import { ADOPTION_LEFT_OUT, type AdoptionStatus } from "@mehen/protocol/adopt"
import { segments, type Text } from "../tty.ts"
import { type AdoptPlan, type PlanProject, uploadedSources } from "./plan.ts"

export type InventorySource = { path: string; variable: string | null; pointer: string | null; mtime: string | null; stale: string[] }
export type InventoryUse = { project: string; env: string; variable: string }
export type InventoryItem = { ref: string; slug: string; kind: string; home: "private" | "workspace" | "project"; project: string | null; include: boolean; exists: boolean; stale: boolean; storeOnly: boolean; sources: InventorySource[]; uses: InventoryUse[] }

// What became of one of this machine's rows in a batch: `left-out` is a row
// unticked at review, or one it sent that an approved batch neither stored,
// mapped, replaced nor refused; `waiting` a row of a batch still open. `slug` names the item a decided
// row's variables use; `reason` is the vault's own, for a refused row.
export type InventoryOutcome = "created" | "mapped" | "replaced" | "refused" | "left-out" | "waiting"
export type InventoryRow = { ref: string; outcome: InventoryOutcome; slug: string | null; reason: string | null }
// `status` null: the vault no longer answers for the batch, so its
// outcomes are unknown.
export type InventoryBatch = { adoption: string; status: AdoptionStatus["status"] | null; expiresAt: string | null; url: string | null; rows: InventoryRow[] }

export type AdoptInventory = { plan: string; workspace: string; machine: string; items: InventoryItem[]; batches: InventoryBatch[]; url: string | null }

// Every plan item, ticked or not, with where it was found and the
// variables it backs, by project slug.
export function inventoryItems(plan: AdoptPlan): InventoryItem[] {
  const stale = new Set(plan.possiblyStale.map((s) => s.source))
  const storeOnly = new Set(plan.storeOnly.map((s) => s.ref))
  const targets: { project: PlanProject; env: string; vars: AdoptPlan["services"][number]["vars"] }[] = [...plan.repos.flatMap((r) => r.files.map((f) => ({ project: r.project, env: f.env, vars: f.vars }))), ...plan.services.map((s) => ({ project: s.project, env: s.env, vars: s.vars }))]
  return plan.items.map((item) => {
    const ids = uploadedSources(item)
    const sources = ids.flatMap((id) => {
      const s = plan.sources[id]
      return s ? [{ path: s.path, variable: s.variable, pointer: s.pointer, mtime: s.mtime ?? null, stale: s.stale }] : []
    })
    return {
      ref: item.ref,
      slug: item.slug,
      kind: item.kind,
      home: item.home.kind,
      project: item.home.kind === "project" ? item.home.project : null,
      include: item.include,
      exists: item.exists,
      stale: ids.some((id) => stale.has(id)) || sources.some((s) => s.stale.length > 0),
      storeOnly: storeOnly.has(item.ref),
      sources,
      uses: targets.flatMap((t) => Object.entries(t.vars).flatMap(([variable, m]) => ("item" in m && m.item === item.ref ? [{ project: t.project.slug, env: t.env, variable }] : []))),
    }
  })
}

// This machine's rows in a batch, from its status by this machine's plan
// refs (statusByPlanRefs). `uploaded` is the plan refs this machine sent to
// it, as the state recorded them; null for a batch from before the state
// kept them, which lists only what the status names.
export function batchRows(status: AdoptionStatus, uploaded: readonly string[] | null): InventoryRow[] {
  const decided = new Map<string, InventoryRow>()
  for (const outcome of ["created", "mapped", "replaced"] as const) for (const c of status[outcome] ?? []) decided.set(c.ref, { ref: c.ref, outcome, slug: c.slug, reason: null })
  for (const r of status.refused ?? []) decided.set(r.ref, r.reason === ADOPTION_LEFT_OUT ? { ref: r.ref, outcome: "left-out", slug: null, reason: null } : { ref: r.ref, outcome: "refused", slug: null, reason: r.reason })
  if (uploaded === null) return [...decided.values()]
  if (status.status !== "approved" && status.status !== "open") return []
  return uploaded.map((ref) => decided.get(ref) ?? { ref, outcome: status.status === "open" ? "waiting" : "left-out", slug: null, reason: null })
}

function itemLines(item: InventoryItem): Text[] {
  const home = item.home === "project" ? `project:${item.project ?? "?"}` : item.home
  const marks = [item.include ? "included" : "not included", ...(item.exists ? ["already in the vault"] : []), ...(item.stale ? ["possibly stale"] : []), ...(item.storeOnly ? ["stored only"] : [])]
  return [
    segments(`${item.ref} ${item.slug} (${item.kind}, ${home}): ${marks.join(", ")}`),
    ...item.sources.map((s) => segments(`  from ${s.path}${s.variable ? ` ${s.variable}` : s.pointer ? ` ${s.pointer}` : ""}${s.mtime ? `, changed ${s.mtime}` : ""}`)),
    ...item.uses.map((u) => segments(`  used by ${u.project} ${u.env}: ${u.variable}`)),
  ]
}

const OUTCOME_TEXT: Record<InventoryOutcome, string> = { created: "created", mapped: "mapped to", replaced: "replaced", refused: "refused", "left-out": "left out", waiting: "waiting for review" }

function batchLines(batch: InventoryBatch): Text[] {
  if (batch.status === null) return [segments(`batch ${batch.adoption}: the vault no longer answers for it; outcomes unknown`)]
  return [
    segments(`batch ${batch.adoption}: ${batch.status}, expires ${batch.expiresAt}${batch.url ? `; ${batch.url}` : ""}`),
    ...batch.rows.map((r) => segments(`  ${r.ref}: ${OUTCOME_TEXT[r.outcome]}${r.slug ? ` ${r.slug}` : ""}${r.reason ? `: ${r.reason}` : ""}`)),
  ]
}

export function inventoryLines(inventory: AdoptInventory): Text[] {
  const included = inventory.items.filter((i) => i.include).length
  return [
    `${inventory.plan}: ${inventory.items.length} item${inventory.items.length === 1 ? "" : "s"} (${included} included) for workspace ${inventory.workspace} on ${inventory.machine}`,
    ...inventory.items.flatMap(itemLines),
    ...(inventory.batches.length ? inventory.batches.flatMap(batchLines) : ["this machine has submitted no batch for this workspace"]),
    inventory.url ? `inventory page: ${inventory.url}` : "inventory page: the workspace's adopt page in the vault (this machine has no workspace slug to link it)",
  ]
}
