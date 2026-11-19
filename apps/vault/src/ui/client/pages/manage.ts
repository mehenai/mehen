// The search, sort and filter chips on the list pages, all over rows the
// page already rendered: nothing here fetches. `/` to focus the search is
// in shortcuts.ts with the other keys.

import { all, find } from "../dom.ts"

// ---------------------------------------------------------------- lists

type Filter = { chip: string; value: string }

function rowMatches(row: HTMLElement, query: string, filter: Filter): boolean {
  const d = row.dataset
  if (query !== "" && !(d.search ?? "").includes(query)) return false
  switch (filter.chip) {
    case "all":
      return true
    case "attention":
      return d.attention === "1"
    case "protected":
      return d.protected === "1"
    case "kind":
      return d.kind === filter.value
    case "tag":
      return (d.tags ?? "").split(" ").includes(filter.value)
    case "group":
      return d.group === filter.value
    case "outcome":
      return d.outcome === filter.value
    default:
      return true
  }
}

const SORTS: Record<string, (a: HTMLElement, b: HTMLElement) => number> = {
  used: (a, b) => Number(b.dataset.used ?? 0) - Number(a.dataset.used ?? 0) || (a.dataset.name ?? "").localeCompare(b.dataset.name ?? ""),
  name: (a, b) => (a.dataset.name ?? "").localeCompare(b.dataset.name ?? ""),
  attention: (a, b) => Number(b.dataset.attention ?? 0) - Number(a.dataset.attention ?? 0) || Number(b.dataset.used ?? 0) - Number(a.dataset.used ?? 0),
  calls: (a, b) => Number(b.dataset.calls ?? 0) - Number(a.dataset.calls ?? 0),
}

// Search, sort and chips over `[data-row]` elements: each row carries what
// it can be matched and ordered on in data attributes, and the page's
// result line and "nothing matches" state follow. `/` focuses the search.
export function initList(): void {
  const list = find('[data-region="list"]')
  if (!list) return
  const rows = all('[data-row]', list)
  const search = find<HTMLInputElement>('[data-input="search"]')
  const sort = find<HTMLSelectElement>('[data-input="sort"]')
  const chips = all<HTMLButtonElement>('[data-region="chips"] .chip')
  const count = find('[data-region="result-count"]')
  const none = find('[data-region="no-match"]')
  const total = count?.textContent ?? ""
  let filter: Filter = { chip: "all", value: "" }

  const apply = () => {
    const query = (search?.value ?? "").trim().toLowerCase()
    let shown = 0
    for (const row of rows) {
      const match = rowMatches(row, query, filter)
      row.hidden = !match
      if (match) shown++
    }
    if (none) none.hidden = shown > 0
    if (count) count.textContent = query === "" && filter.chip === "all" ? total : `${shown} of ${rows.length} shown`
  }

  search?.addEventListener("input", apply)
  for (const chip of chips) {
    chip.addEventListener("click", () => {
      filter = { chip: chip.dataset.chip ?? "all", value: chip.dataset.value ?? "" }
      for (const other of chips) other.setAttribute("aria-pressed", other === chip ? "true" : "false")
      apply()
    })
  }
  const reorder = () => {
    const by = sort ? SORTS[sort.value] : undefined
    if (!by) return
    for (const row of [...rows].sort(by)) list.append(row)
  }
  sort?.addEventListener("change", reorder)
  // The browser may restore another choice on Back; the rows follow it.
  reorder()
}
