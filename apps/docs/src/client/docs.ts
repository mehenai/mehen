// The docs pages' one script, and every page works without it: the copy
// button on code (the app's wireCopy), the colour scheme toggle, and search
// as you type over /search-index.json with the same scoring the Worker's
// /search uses. Enter still submits the form to /search.

import { type SearchEntry, search } from "../search.ts"

const THEME_KEY = "mehen-docs-theme"
const COPIED_FOR_MS = 1200
const SUGGESTIONS = 8

type Theme = "light" | "dark" | null

// A <button data-copy> copies the text of the <code> beside it and reads
// "Copied" for a moment.
function wireCopy(): void {
  document.addEventListener("click", (event) => {
    const button = (event.target as Element | null)?.closest<HTMLButtonElement>("button[data-copy]")
    if (!button) return
    const code = button.parentElement?.querySelector("code")
    const text = code?.textContent ?? ""
    if (text === "") return
    void navigator.clipboard.writeText(text).then(() => {
      const label = button.querySelector("span") ?? button
      const before = label.textContent
      label.textContent = "Copied"
      setTimeout(() => {
        label.textContent = before
      }, COPIED_FOR_MS)
    })
  })
}

function storedTheme(): Theme {
  try {
    const value = localStorage.getItem(THEME_KEY)
    return value === "light" || value === "dark" ? value : null
  } catch {
    return null
  }
}

function applyTheme(theme: Theme): void {
  const root = document.documentElement
  if (theme === null) delete root.dataset.theme
  else root.dataset.theme = theme
  const metas = document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]')
  metas.forEach((meta, n) => meta.setAttribute("content", theme === "dark" ? "#0f1626" : theme === "light" ? "#f3ead8" : n === 0 ? "#f3ead8" : "#0f1626"))
  try {
    if (theme === null) localStorage.removeItem(THEME_KEY)
    else localStorage.setItem(THEME_KEY, theme)
  } catch {
    // Not kept; it still applies to this page.
  }
}

const THEME_WORDS: Record<"light" | "dark" | "system", string> = { light: "Light", dark: "Dark", system: "System" }

// Light, dark, then the system's scheme again.
function wireTheme(): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>("[data-theme-toggle]")
  const label = (theme: Theme) => {
    for (const button of buttons) {
      const span = button.querySelector("span") ?? button
      span.textContent = THEME_WORDS[theme ?? "system"]
      button.setAttribute("aria-label", `Colour scheme: ${THEME_WORDS[theme ?? "system"]}. Switch it`)
    }
  }
  label(storedTheme())
  for (const button of buttons) {
    button.hidden = false
    button.addEventListener("click", () => {
      const current = storedTheme()
      const next: Theme = current === null ? "light" : current === "light" ? "dark" : null
      applyTheme(next)
      label(next)
    })
  }
}

function wireSearch(): void {
  const form = document.querySelector<HTMLFormElement>("form.search")
  const input = form?.querySelector<HTMLInputElement>("input[name=q]")
  const list = form?.querySelector<HTMLUListElement>(".search-results")
  if (!form || !input || !list) return
  let entries: SearchEntry[] | null = null
  let loading: Promise<void> | null = null
  const load = () => {
    loading ??= fetch("/search-index.json")
      .then((r) => (r.ok ? (r.json() as Promise<SearchEntry[]>) : []))
      .then((loaded) => {
        entries = loaded
      })
      .catch(() => {
        entries = []
      })
    return loading
  }
  const clear = () => {
    list.replaceChildren()
    list.hidden = true
  }
  const show = () => {
    if (entries === null) return
    const hits = search(entries, input.value, SUGGESTIONS)
    if (hits.length === 0) return clear()
    list.replaceChildren(
      ...hits.map((hit) => {
        const item = document.createElement("li")
        const link = document.createElement("a")
        link.href = hit.u
        const page = document.createElement("strong")
        page.textContent = hit.t
        const heading = document.createElement("span")
        heading.textContent = hit.h
        link.append(page, heading)
        item.append(link)
        return item
      }),
    )
    list.hidden = false
  }
  input.addEventListener("focus", () => void load(), { once: true })
  input.addEventListener("input", () => void load().then(show))
  input.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      input.value = ""
      clear()
    }
  })
  document.addEventListener("click", (event) => {
    if (!form.contains(event.target as Node)) clear()
  })
}

wireCopy()
wireTheme()
wireSearch()
