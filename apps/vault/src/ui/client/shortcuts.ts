// Keyboard shortcuts: `/` focuses the list search, `G` then a letter goes
// to a place, `J` and `K` move between rows, `?` opens the sheet, and on an
// approval `T`, `W`, `D` and `Y` move focus to the tick, the whole truth,
// Deny and Approve. Nothing here clicks, submits or decides: a key only
// ever moves focus, and the passkey still confirms. Keys are ignored while
// typing, while the palette or the sheet is open, with a modifier held,
// and on a touch screen.

import { isVaultPath } from "../html.ts"
import { all, find } from "./dom.ts"
import { APPROVAL_KEYS, GO_PLACES, GO_WINDOW_MS, isTyping, nextRowIndex } from "./shortcut-keys.ts"

function isTouchScreen(): boolean {
  return matchMedia("(hover: none) and (pointer: coarse)").matches
}

type Sheet = { open(): void; close(): void; isOpen(): boolean }

function initSheet(): Sheet | null {
  const scrim = find('[data-region="shortcuts"]')
  if (!scrim) return null
  const closeButton = find<HTMLButtonElement>('[data-action="close-shortcuts"]', scrim)
  let opener: HTMLElement | null = null
  const isOpen = () => !scrim.hidden
  const close = () => {
    if (!isOpen()) return
    scrim.hidden = true
    const back = opener
    opener = null
    back?.focus()
  }
  const open = () => {
    if (isOpen()) return
    opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    scrim.hidden = false
    closeButton?.focus()
  }
  closeButton?.addEventListener("click", close)
  scrim.addEventListener("click", (event) => {
    if (event.target === scrim) close()
  })
  scrim.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault()
      event.stopPropagation()
      close()
    }
    // One focusable control: Tab stays on it.
    if (event.key === "Tab") event.preventDefault()
  })
  return { open, close, isOpen }
}

function visibleRows(): HTMLAnchorElement[] {
  return all<HTMLAnchorElement>("a.row-main").filter((a) => a.offsetParent !== null)
}

function focusOnly(selector: string): void {
  const node = find<HTMLElement>(selector)
  if (!node) return
  if (node instanceof HTMLButtonElement && node.disabled) return
  node.focus()
}

function jumpTo(selector: string): boolean {
  const node = find<HTMLElement>(selector)
  if (!node) return false
  node.tabIndex = -1
  node.scrollIntoView({ block: "start", behavior: "smooth" })
  node.focus({ preventScroll: true })
  return true
}

export function initShortcuts(paletteOpen: () => boolean, places: Record<string, string> = GO_PLACES): void {
  const sheet = initSheet()
  if (isTouchScreen()) return
  let goUntil = 0

  document.addEventListener("keydown", (event) => {
    if (event.metaKey || event.ctrlKey || event.altKey || event.defaultPrevented) return
    // The catalogue's start sheet is modal too: no key reaches the page behind it.
    if (isTyping(event.target) || paletteOpen() || (sheet?.isOpen() ?? false) || document.body.classList.contains("sheet-open")) return
    const key = event.key
    const now = Date.now()

    if (key === "?") {
      event.preventDefault()
      sheet?.open()
      return
    }
    if (key === "/") {
      const search = find<HTMLInputElement>('[data-input="search"]')
      if (!search) return
      event.preventDefault()
      search.focus()
      return
    }

    const lower = key.toLowerCase()
    if (goUntil > now) {
      goUntil = 0
      const place = Object.hasOwn(places, lower) ? places[lower] : undefined
      if (place !== undefined && isVaultPath(place)) {
        event.preventDefault()
        location.assign(place)
      }
      return
    }
    if (lower === "g") {
      goUntil = now + GO_WINDOW_MS
      return
    }
    if (lower === "j" || lower === "k") {
      const rows = visibleRows()
      const current = rows.findIndex((r) => r === document.activeElement)
      const row = rows[nextRowIndex(rows.length, current, lower === "j" ? 1 : -1)]
      if (!row) return
      event.preventDefault()
      row.focus()
      return
    }
    const action = APPROVAL_KEYS[lower]
    if (action === undefined) return
    if (action.kind === "jump") {
      if (jumpTo(action.selector)) event.preventDefault()
      return
    }
    focusOnly(action.selector)
  })
}
