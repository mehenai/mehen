// The adoption review page's rules, shared by the server page and its
// script: which rows start ticked, how rows group, the decisions the page
// signs and what the decision bar says about them. No value is ever here:
// the view carries lengths, prefixes and fingerprints only.

import type { ApiError } from "@mehen/protocol/api"
import { Slug } from "@mehen/protocol/api"
import { ADOPTION_LIMITS, type AdoptionAction, type AdoptionCompareResult, type AdoptionDecisionInput, type WorkspaceAdoptionItemView, type WorkspaceAdoptionView, adoptionDigest, adoptionRepoints } from "@mehen/protocol/adopt"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import type { WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { isLeaseOnly } from "@mehen/protocol/binding"
import type { CredentialHome } from "@mehen/protocol/workspace"
import { ADOPTION_HOLDER_GONE } from "../../../adoption-words.ts"
import { homeKey, homeOfKey } from "../../home-key.ts"
import { adoptionCount } from "../../wording.ts"
import { CHANGED_SINCE_SHOWN, sameAction } from "../workspace-logic.ts"

// A compare row's result for one secret field, in words.
export const ADOPTION_RESULT_WORDS: Record<AdoptionCompareResult, string> = { same: "same value", differs: "different value", unknown: "could not be compared" }

// A destination no template vouches for. A lease-only row has none.
export function adoptionCustom(item: WorkspaceAdoptionItemView): boolean {
  return !item.binding.verified && !isLeaseOnly(item.binding.value)
}

// Every source the machine found is marked stale (an old file, a commented
// line). A value also in a fresh file is current, as the CLI's plan has it.
export function adoptionStale(item: WorkspaceAdoptionItemView): boolean {
  return item.sources.length > 0 && item.sources.every((s) => s.stale.length > 0)
}

// Ticked unless the row has a problem, only stale sources or a custom destination.
export function adoptionTickedByDefault(item: WorkspaceAdoptionItemView): boolean {
  return item.problem === null && !adoptionStale(item) && !adoptionCustom(item)
}

// The home a row starts with in its selector: its proposed home when this
// person may choose it, else none, so ticking it needs a choice.
export function adoptionStartHome(item: WorkspaceAdoptionItemView): CredentialHome | null {
  return homeOfKey(homeKey(item.home), item.homesAllowed)
}

export type AdoptionGroup = { repo: string; folders: { folder: string; items: WorkspaceAdoptionItemView[] }[] }

export const NO_REPO_WORDS = "Not in a repository"

function repoWords(item: WorkspaceAdoptionItemView): string {
  const where = item.repo?.remote ?? NO_REPO_WORDS
  const env = item.repo?.env ?? null
  return env !== null ? `${where}, environment ${env}` : where
}

function folderOf(item: WorkspaceAdoptionItemView): string {
  const path = item.sources[0]?.path ?? ""
  const cut = path.lastIndexOf("/")
  return cut <= 0 ? "/" : path.slice(0, cut)
}

function byCodeUnit(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

// Rows grouped by repository then by the folder of their first source,
// each in code-unit order, rows by ref within a folder.
export function adoptionGroups(items: readonly WorkspaceAdoptionItemView[]): AdoptionGroup[] {
  const repos = new Map<string, Map<string, WorkspaceAdoptionItemView[]>>()
  for (const item of items) {
    const folders = repos.get(repoWords(item)) ?? new Map<string, WorkspaceAdoptionItemView[]>()
    repos.set(repoWords(item), folders)
    folders.set(folderOf(item), [...(folders.get(folderOf(item)) ?? []), item])
  }
  return [...repos.entries()].sort(([a], [b]) => byCodeUnit(a, b)).map(([repo, folders]) => ({
    repo,
    folders: [...folders.entries()].sort(([a], [b]) => byCodeUnit(a, b)).map(([folder, rows]) => ({ folder, items: [...rows].sort((x, y) => byCodeUnit(x.ref, y.ref)) })),
  }))
}

// A compare row whose holder is gone or hidden from this reviewer: the
// view shows both alike. Its name is held, or was, so it is never stored
// under it; a copy under another name is what the vault may still take.
export function adoptionHolderGone(item: WorkspaceAdoptionItemView): boolean {
  return (item.compare ?? null) === null && item.problem === ADOPTION_HOLDER_GONE
}

// What a compare row may do, as the vault judges it from what the view
// shows. A row with no compare view and nothing holding its name is only
// stored; one whose holder is gone or hidden only keeps a copy. A row
// compared with another batch's row keeps both until that batch is
// decided; replace needs, for every field, the fingerprint under the
// holder, given only to someone who may replace it, and a holder of the
// same kind.
export function adoptionActions(item: WorkspaceAdoptionItemView, adoption: string): AdoptionAction[] {
  const compare = item.compare ?? null
  if (compare === null) return adoptionHolderGone(item) ? ["rename"] : ["store"]
  const { holder } = compare
  if (holder.type === "staged" && holder.id.split("/")[0] !== adoption) return ["rename"]
  const replaceable = holder.kind === item.kind && compare.fields.length > 0 && compare.fields.every((f) => f.fingerprint !== null)
  return ["map", ...(replaceable ? ["replace" as const] : []), "rename"]
}

// A same value keeps the vault's; a differing or unknown one is decided.
export function adoptionDefaultAction(item: WorkspaceAdoptionItemView, adoption: string): AdoptionAction | null {
  const actions = adoptionActions(item, adoption)
  if (actions.includes("store")) return "store"
  const fields = item.compare?.fields ?? []
  return actions.includes("map") && fields.length > 0 && fields.every((f) => f.result === "same") ? "map" : null
}

function slugPart(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "")
}

function validSlug(slug: string): boolean {
  return Slug.safeParse(slug).success
}

// The name a kept copy is proposed under: <slug>-<env> when the row is in
// a repository environment, else <slug>-<machine>, then -2 and so on past
// every name in `taken`. Editable on the page; the vault checks it is free.
export function adoptionRenameSlug(item: WorkspaceAdoptionItemView, taken: ReadonlySet<string>): string {
  const part = slugPart(item.repo?.env ?? item.sources[0]?.machine ?? "")
  const base = (part === "" ? item.slug : `${item.slug}-${part}`).slice(0, 60).replace(/-+$/, "")
  const free = (slug: string) => validSlug(slug) && !taken.has(slug) && slug !== item.slug
  if (free(base)) return base
  for (let n = 2; ; n++) if (free(`${base}-${n}`)) return `${base}-${n}`
}

// A project variable a kept copy may take over from the holder.
export type AdoptionRepointChoice = { project: string; env: string; variable: string }

// One row as the person left it: the tick, the selector's value and, for a
// compare row, the action (null while undecided), a copy's name and the
// variables ticked to point at it.
export type AdoptionChoice = { include: boolean; home: string; action?: AdoptionAction | null; slug?: string; repoint?: readonly AdoptionRepointChoice[] }

const repointKey = (r: AdoptionRepointChoice) => `${r.project}\n${r.env}\n${r.variable}`

// The ticked variables among those the holder's affected list names (a
// stored holder's references, by the project the view gives), in the
// order the digest signs them; none is no repoint.
function repointOf(item: WorkspaceAdoptionItemView, chosen: readonly AdoptionRepointChoice[]): AdoptionRepointChoice[] | null {
  const ticked = new Set(chosen.map(repointKey))
  const picked = (item.compare?.affected?.references ?? []).filter((r) => ticked.has(repointKey(r))).map((r) => ({ project: r.project, env: r.env, variable: r.variable }))
  return picked.length === 0 ? null : picked.sort((a, b) => byCodeUnit(repointKey(a), repointKey(b)))
}

const NOTHING_SIGNED = { say: "Nothing was signed." }
export const ADOPTION_HOME_NEEDED = (slug: string): ApiError => ({ error: "bad_request", message: `Choose where ${slug} belongs, or untick it.`, next: NOTHING_SIGNED })
export const ADOPTION_DECISION_NEEDED = (slug: string): ApiError => ({ error: "bad_request", message: `Decide what happens to ${slug}: keep the vault's value, replace it or keep both under another name; or untick it.`, next: NOTHING_SIGNED })
export const ADOPTION_RENAME_INVALID = (slug: string): ApiError => ({ error: "bad_request", message: `Choose another name for the copy of ${slug}: lowercase letters, digits and single hyphens, 2 to 64 characters, starting with a letter, and no other row's name.`, next: NOTHING_SIGNED })

// The decisions the passkey signs: one per row of the view. A ticked row
// has a home this person may choose and an explicit action: store for a
// row that is only stored, which signs what it signed before actions
// existed, else the one the person chose among those the row may take. An
// unticked row keeps its proposed home, which is not signed.
export function adoptionDecisions(adoption: string, items: readonly WorkspaceAdoptionItemView[], choices: ReadonlyMap<string, AdoptionChoice>): { ok: true; decisions: AdoptionDecisionInput[] } | { ok: false; error: ApiError } {
  const included = (item: WorkspaceAdoptionItemView) => choices.get(item.ref)?.include === true
  const renamed = (item: WorkspaceAdoptionItemView) => (choices.get(item.ref)?.action === "rename" ? (choices.get(item.ref)?.slug ?? "").trim() : null)
  const decisions: AdoptionDecisionInput[] = []
  for (const item of items) {
    const choice = choices.get(item.ref)
    if (choice === undefined || !choice.include) {
      decisions.push({ ref: item.ref, include: false, home: item.home })
      continue
    }
    const home = homeOfKey(choice.home, item.homesAllowed)
    if (home === null) return { ok: false, error: ADOPTION_HOME_NEEDED(item.slug) }
    const actions = adoptionActions(item, adoption)
    const action = actions.includes("store") ? "store" : (choice.action ?? null)
    if (action === null || !actions.includes(action)) return { ok: false, error: ADOPTION_DECISION_NEEDED(item.slug) }
    if (action !== "rename") {
      decisions.push({ ref: item.ref, include: true, home, action })
      continue
    }
    const slug = renamed(item) ?? ""
    const elsewhere = items.some((other) => other.slug === slug || (other.ref !== item.ref && included(other) && renamed(other) === slug))
    if (!validSlug(slug) || elsewhere || slug === item.compare?.holder.slug) return { ok: false, error: ADOPTION_RENAME_INVALID(item.slug) }
    const repoint = repointOf(item, choice.repoint ?? [])
    decisions.push({ ref: item.ref, include: true, home, action, slug, ...(repoint !== null ? { repoint } : {}) })
  }
  return { ok: true, decisions }
}

function undecided(adoption: string, item: WorkspaceAdoptionItemView, choice: AdoptionChoice | undefined): boolean {
  const actions = adoptionActions(item, adoption)
  return !actions.includes("store") && (choice?.action == null || !actions.includes(choice.action))
}

// The ticked compare rows with no action they may take: approval waits for them.
export function adoptionUndecided(adoption: string, items: readonly WorkspaceAdoptionItemView[], choices: ReadonlyMap<string, AdoptionChoice>): number {
  return items.filter((i) => choices.get(i.ref)?.include === true && undecided(adoption, i, choices.get(i.ref))).length
}

export function adoptionUndecidedWords(n: number): string {
  return n === 1 ? "1 row needs a decision before you approve." : `${n} rows need a decision before you approve.`
}

// "Keep the vault's value for every remaining one": the undecided compare
// rows, ticked or not, that may keep the value already held.
export function adoptionKeepVaultRefs(adoption: string, items: readonly WorkspaceAdoptionItemView[], choices: ReadonlyMap<string, AdoptionChoice>): string[] {
  return items.filter((i) => undecided(adoption, i, choices.get(i.ref)) && adoptionActions(i, adoption).includes("map")).map((i) => i.ref)
}

// What the passkey signs, from the rows the page showed and the decisions.
export async function adoptionApproveAction(adoption: string, items: readonly WorkspaceAdoptionItemView[], decisions: readonly AdoptionDecisionInput[]): Promise<Extract<WorkspaceStepUpAction, { type: "adoption.approve" }>> {
  return { type: "adoption.approve", adoption, digest: await adoptionDigest(adoption, items, decisions), repoints: adoptionRepoints(decisions) }
}

// A row as the full-row check compares it: without a stored holder's last
// use and lease count, which move whenever someone uses the credential.
function withoutUsage(item: WorkspaceAdoptionItemView): WorkspaceAdoptionItemView {
  const compare = item.compare ?? null
  if (compare === null) return item
  const holder = compare.holder.type === "stored" ? { ...compare.holder, lastUsedAt: null } : compare.holder
  const affected = compare.affected === undefined ? {} : { affected: { ...compare.affected, leasingDevices: 0 } }
  return { ...item, compare: { ...compare, holder, ...affected } }
}

// The batch read again just before signing, as the vault will rebuild the
// action from it: refused unless it is still open, its rows are the ones
// shown but for the holder's use, and the same decisions over it give the
// very action expected.
export async function adoptionShownRefusal(expected: WorkspaceStepUpAction, shown: readonly WorkspaceAdoptionItemView[], now: WorkspaceAdoptionView, decisions: readonly AdoptionDecisionInput[]): Promise<ApiError | null> {
  if (now.status !== "open" || canonicalJson(now.items.map(withoutUsage)) !== canonicalJson(shown.map(withoutUsage))) return CHANGED_SINCE_SHOWN
  return sameAction(expected, await adoptionApproveAction(now.adoption, now.items, decisions)) ? null : CHANGED_SINCE_SHOWN
}

// What one click adds: keepOpenMs, or less once the batch nears the longest
// it may stay open; in whole days when it is, else whole hours or minutes,
// never more than it adds.
export function adoptionKeepOpenWords(view: Pick<WorkspaceAdoptionView, "expiresAt" | "maxExpiresAt">): string {
  const adds = Math.min(ADOPTION_LIMITS.keepOpenMs, Date.parse(view.maxExpiresAt ?? view.expiresAt) - Date.parse(view.expiresAt))
  const more = (n: number, unit: string) => `Keep open ${n} more ${unit}${n === 1 ? "" : "s"}`
  if (adds % 86_400_000 === 0) return more(adds / 86_400_000, "day")
  if (adds >= 3_600_000) return more(Math.floor(adds / 3_600_000), "hour")
  return more(Math.floor(adds / 60_000), "minute")
}

// Keep-open is offered while one click still adds at least a minute before
// the longest the batch may stay open; a vault that does not say how long
// offers none.
export function adoptionKeepOpenShown(view: Pick<WorkspaceAdoptionView, "expiresAt" | "maxExpiresAt">): boolean {
  return view.maxExpiresAt !== undefined && Date.parse(view.maxExpiresAt) - Date.parse(view.expiresAt) >= 60_000
}

export function adoptionApproveLabel(included: number): string {
  return `Approve ${adoptionCount(included)}`
}

// "8 to Whole workspace, 4 to Only me": the ticked rows by the home each
// would be stored in, in the order the homes are offered.
export function adoptionHomeCounts(choices: Iterable<AdoptionChoice>, labels: readonly (readonly [key: string, label: string])[]): string {
  const counts = new Map<string, number>()
  for (const c of choices) if (c.include) counts.set(c.home, (counts.get(c.home) ?? 0) + 1)
  const named = labels.filter(([key]) => counts.has(key)).map(([key, label]) => `${counts.get(key)} to ${label}`)
  const unchosen = [...counts.entries()].filter(([key]) => !labels.some(([k]) => k === key)).reduce((n, [, c]) => n + c, 0)
  return [...named, ...(unchosen > 0 ? [`${unchosen} with no home chosen`] : [])].join(", ")
}

// The rows an all-or-nothing refusal named, with the vault's reason.
export function adoptionRefusals(error: ApiError): Map<string, string> {
  return new Map((error.refused ?? []).map((r) => [r.ref, r.reason]))
}
