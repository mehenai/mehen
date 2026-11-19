// The command palette: ⌘K, Ctrl K or the rail's Search button opens it over
// the page. Its contents come from the lists the member can already read,
// fetched on first open and kept for this page view; the search and the
// order are in palette-logic.ts. On a workspace page the lists are that
// workspace's, kept under the tab's full identity, and dropped if the tab
// goes stale while they load. Every node is built with createElement and
// textContent (matches are <mark> elements, never markup); every string a
// person or an agent wrote is spelled with the server's own rules, so a
// hidden character shows as the same <mark class="marker"> the pages use;
// and every link is checked as a vault path before it becomes an href.

import type { DeviceView, ItemSummary, PendingList, Project } from "@mehen/protocol/api"
import type { WorkspacePendingAsk, WorkspaceSettingsView } from "@mehen/protocol/workspace"
import { isVaultPath } from "../html.ts"
import { api, workspaceRead } from "./api.ts"
import { all, el, find, markerNode, must, spelledNodes } from "./dom.ts"
import { GROUP_WORDS, type PaletteEntry, type PaletteMatch, type PaletteScope, type PaletteSources, type PaletteTile, VAULT_SCOPE, buildEntries, filterEntries, timeLeftWords, titlePieces, workspacePaletteAsks } from "./palette-logic.ts"
import type { ShellState } from "./shell-logic.ts"
import { paletteKeyWords } from "./shortcut-keys.ts"

function platformName(): string {
  const data = (navigator as Navigator & { userAgentData?: { platform?: unknown } }).userAgentData
  return typeof data?.platform === "string" && data.platform !== "" ? data.platform : navigator.platform
}

async function optional<T>(path: string): Promise<T | null> {
  try {
    return await api<T>(path)
  } catch {
    return null
  }
}

// A workspace read the server serves, or null: a read it does not serve is
// never asked for.
async function workspaceOptional<T>(shell: ShellState, path: string): Promise<T | null> {
  if (!shell.identity.reads.includes(path)) return null
  try {
    return await workspaceRead<T>(shell, path)
  } catch {
    return null
  }
}

async function loadWorkspaceSources(shell: ShellState): Promise<PaletteSources> {
  const [pending, items, devices, projects, settings] = await Promise.all([
    workspaceOptional<{ pending: WorkspacePendingAsk[] }>(shell, "/pending"),
    workspaceOptional<{ items: ItemSummary[] }>(shell, "/items"),
    workspaceOptional<{ devices: DeviceView[] }>(shell, "/devices"),
    workspaceOptional<{ projects: Project[] }>(shell, "/projects"),
    workspaceOptional<WorkspaceSettingsView>(shell, "/settings"),
  ])
  return { pending: pending !== null ? workspacePaletteAsks(pending.pending) : null, items: items?.items ?? null, devices: devices?.devices ?? null, projects: projects?.projects ?? null, settings }
}

async function loadSources(): Promise<PaletteSources> {
  const [pending, items, devices, projects] = await Promise.all([
    optional<PendingList>("/api/pending"),
    optional<{ items: ItemSummary[] }>("/api/items"),
    optional<{ devices: DeviceView[] }>("/api/devices"),
    optional<{ projects: Project[] }>("/api/projects"),
  ])
  return { pending: pending?.pending ?? null, items: items?.items ?? null, devices: devices?.devices ?? null, projects: projects?.projects ?? null }
}

// Tiles are cloned from the <template>s the shell renders beside the
// palette, so no SVG is ever built from a string here.
function tileNode(tiles: HTMLElement, tile: PaletteTile): HTMLElement {
  if (tile.kind === "letter") {
    const span = el("span", "tile letter")
    span.setAttribute("aria-hidden", "true")
    span.append(el("span", null, tile.letter))
    return span
  }
  const key = tile.kind === "brand" ? `brand:${tile.slug}` : `icon:${tile.name}`
  const template = find<HTMLTemplateElement>(`template[data-tile="${key}"]`, tiles) ?? find<HTMLTemplateElement>('template[data-tile="icon:key"]', tiles)
  const wrapper = el("span", tile.kind === "brand" ? "tile" : "tile kind")
  if (template) wrapper.append(template.content.cloneNode(true))
  return wrapper
}

// The title spelled, with the search's matched ranges as <mark> and the
// vault's markers as <mark class="marker">, all built from text.
function titleNode(match: PaletteMatch): HTMLElement {
  const b = el("b", null)
  for (const piece of titlePieces(match.entry.title, match.ranges)) {
    if (piece.kind === "marker") b.append(markerNode(piece.text))
    else if (piece.kind === "match") b.append(el("mark", null, piece.text))
    else b.append(document.createTextNode(piece.text))
  }
  return b
}

function itemNode(tiles: HTMLElement, match: PaletteMatch, id: string, now: number): HTMLAnchorElement | null {
  const entry = match.entry
  if (!isVaultPath(entry.href)) return null
  const a = el("a", "palette-item") as HTMLAnchorElement
  a.href = entry.href
  a.id = id
  a.setAttribute("role", "option")
  a.setAttribute("aria-selected", "false")
  a.tabIndex = -1
  a.append(tileNode(tiles, entry.tile))
  const text = el("span", "text")
  text.append(titleNode(match))
  // The time left leads the line, so a narrow screen cuts the sub, not it.
  const left = timeLeftWords(entry, now)
  const sub = el("span", null)
  if (left !== null) sub.append(document.createTextNode(`${left} · `))
  sub.append(...spelledNodes(entry.sub))
  text.append(sub)
  a.append(text)
  if (entry.action !== null) a.append(el("span", "pill muted", entry.action))
  return a
}

export type PaletteHandle = { open(from?: HTMLElement): void; close(): void; isOpen(): boolean }

export function initPalette(shell: ShellState | null = null): PaletteHandle | null {
  const scrim = find('[data-region="palette"]')
  if (!scrim) return null
  const scope: PaletteScope = shell === null ? VAULT_SCOPE : { kind: "workspace", slug: shell.identity.workspace.slug, name: shell.identity.workspace.name, pages: shell.identity.pages, reads: shell.identity.reads }
  const input = must<HTMLInputElement>("input", scrim)
  const list = must('[role="listbox"]', scrim)
  const tiles = must('[data-region="palette-tiles"]', scrim)
  let entries: PaletteEntry[] | null = null
  let loading: Promise<void> | null = null
  let shown: HTMLAnchorElement[] = []
  let selected = -1
  let opener: HTMLElement | null = null

  const select = (index: number) => {
    selected = shown.length === 0 ? -1 : Math.max(0, Math.min(shown.length - 1, index))
    shown.forEach((node, i) => node.setAttribute("aria-selected", i === selected ? "true" : "false"))
    const current = shown[selected]
    if (current) {
      input.setAttribute("aria-activedescendant", current.id)
      current.scrollIntoView({ block: "nearest" })
    } else input.removeAttribute("aria-activedescendant")
  }

  const render = () => {
    const now = Date.now()
    list.replaceChildren()
    shown = []
    const refusal = shell?.refusal() ?? null
    if (refusal !== null) {
      list.append(el("p", "palette-note", refusal.message))
      select(-1)
      return
    }
    if (entries === null) {
      list.append(el("p", "palette-note", "Loading..."))
      select(-1)
      return
    }
    const matches = filterEntries(entries, input.value)
    let group: string | null = null
    let n = 0
    for (const match of matches) {
      if (match.entry.group !== group) {
        group = match.entry.group
        const head = el("div", "palette-group", GROUP_WORDS[match.entry.group])
        head.setAttribute("role", "presentation")
        list.append(head)
      }
      const node = itemNode(tiles, match, `palette-item-${n++}`, now)
      if (!node) continue
      list.append(node)
      shown.push(node)
    }
    if (shown.length === 0) list.append(el("p", "palette-note", input.value.trim() === "" ? "Nothing to show yet." : "Nothing matches."))
    select(0)
  }

  const load = () => {
    if (entries !== null || loading !== null || shell?.stale) return
    const start = shell?.begin()
    loading = (shell === null ? loadSources() : loadWorkspaceSources(shell)).then((sources) => {
      loading = null
      // Lists that landed after the tab went stale or moved on are dropped.
      if (shell !== null && (start === undefined || !start.ok || shell.settle(start.generation) !== null)) {
        render()
        return
      }
      entries = buildEntries(sources, Date.now(), scope)
      render()
    })
  }

  const isOpen = () => !scrim.hidden

  const close = () => {
    if (!isOpen()) return
    scrim.hidden = true
    input.setAttribute("aria-expanded", "false")
    document.body.classList.remove("palette-open")
    const back = opener
    opener = null
    back?.focus()
  }

  // `from` is the button that opened it (a click does not focus a button in
  // every browser); otherwise focus goes back to whatever had it.
  const open = (from?: HTMLElement) => {
    if (isOpen()) return
    opener = from ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null)
    scrim.hidden = false
    input.setAttribute("aria-expanded", "true")
    document.body.classList.add("palette-open")
    input.value = ""
    render()
    load()
    input.focus()
  }

  const go = (newTab: boolean) => {
    const current = shown[selected]
    if (!current) return
    const href = current.getAttribute("href") ?? ""
    if (!isVaultPath(href)) return
    if (newTab) window.open(href, "_blank", "noopener")
    else location.assign(href)
    close()
  }

  input.addEventListener("input", render)
  input.addEventListener("keydown", (event) => {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault()
        select(selected + 1)
        break
      case "ArrowUp":
        event.preventDefault()
        select(selected - 1)
        break
      case "Home":
        if (shown.length > 0) {
          event.preventDefault()
          select(0)
        }
        break
      case "End":
        if (shown.length > 0) {
          event.preventDefault()
          select(shown.length - 1)
        }
        break
      case "Enter":
        event.preventDefault()
        go(event.metaKey || event.ctrlKey)
        break
      case "Tab":
        // Focus stays in the palette while it is open.
        event.preventDefault()
        break
      default:
        break
    }
  })
  scrim.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault()
      event.stopPropagation()
      close()
    }
  })
  scrim.addEventListener("click", (event) => {
    if (event.target === scrim) close()
  })
  find<HTMLButtonElement>('[data-action="close-palette"]', scrim)?.addEventListener("click", close)
  list.addEventListener("click", (event) => {
    const item = (event.target as Element | null)?.closest<HTMLAnchorElement>("a.palette-item")
    if (!item) return
    if (!isVaultPath(item.getAttribute("href") ?? "")) event.preventDefault()
    else close()
  })
  // Keep focus in the palette if it drifts (a click on the scrim's padding).
  scrim.addEventListener("focusout", (event) => {
    if (!isOpen()) return
    const next = event.relatedTarget
    if (next instanceof Node && scrim.contains(next)) return
    if (next === null) return
    input.focus()
  })

  const keyWords = paletteKeyWords(platformName())
  for (const button of all<HTMLButtonElement>('[data-action="palette"]')) {
    button.addEventListener("click", () => open(button))
    const key = find("kbd", button)
    if (key !== null) key.textContent = keyWords
  }
  document.addEventListener("keydown", (event) => {
    if (event.key.toLowerCase() !== "k" || !(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey) return
    event.preventDefault()
    if (isOpen()) close()
    else open()
  })

  return { open, close, isOpen }
}

