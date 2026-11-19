// Small DOM helpers. Text only ever goes in through textContent, so nothing
// the vault or an agent wrote can become markup in the browser either.

import { spellCardSegments } from "../../relay/spelling.ts"
import { VaultFailure } from "./api.ts"

export type Boot = { page: string; [key: string]: unknown }

export function readBoot(): Boot {
  const raw = document.getElementById("app")?.dataset.boot
  if (!raw) return { page: "none" }
  try {
    const value = JSON.parse(raw) as unknown
    return typeof value === "object" && value !== null && typeof (value as Boot).page === "string" ? (value as Boot) : { page: "none" }
  } catch {
    return { page: "none" }
  }
}

export function find<T extends Element = HTMLElement>(selector: string, root: ParentNode = document): T | null {
  return root.querySelector<T>(selector)
}

export function must<T extends Element = HTMLElement>(selector: string, root: ParentNode = document): T {
  const found = root.querySelector<T>(selector)
  if (!found) throw new Error(`page is missing ${selector}`)
  return found
}

export function all<T extends Element = HTMLElement>(selector: string, root: ParentNode = document): T[] {
  return Array.from(root.querySelectorAll<T>(selector))
}

export function el(tag: string, className: string | null, text: string | null = null): HTMLElement {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== null) node.textContent = text
  return node
}

// A marker the vault generated for a hidden character, the same element
// cardText renders on the pages.
export function markerNode(text: string): HTMLElement {
  return el("mark", "marker", text)
}

// Text a human reads, spelled: plain text nodes and marker elements.
export function spelledNodes(text: string): Node[] {
  return spellCardSegments(text).map((s) => (s.kind === "marker" ? markerNode(s.text) : document.createTextNode(s.text)))
}

function safeUrl(url: string): string | null {
  try {
    const parsed = new URL(url, location.origin)
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : null
  } catch {
    return null
  }
}

// The page's notice, or `into`: a notice inside an open modal sheet, where
// the page's own would sit hidden behind the scrim.
function notice(into?: HTMLElement): HTMLElement {
  return into ?? must("#notice")
}

export function clearNotice(into?: HTMLElement): void {
  const box = notice(into)
  box.replaceChildren()
  box.hidden = true
  box.className = "notice"
}

function showNotice(tone: "error" | "info" | "warn", lines: HTMLElement[], into?: HTMLElement): void {
  const box = notice(into)
  box.className = `notice ${tone}`
  box.replaceChildren(...lines)
  box.hidden = false
  box.scrollIntoView({ block: "start", behavior: "smooth" })
}

export function showInfo(text: string): void {
  showNotice("info", [el("p", null, text)])
}

export function showProblems(problems: string[], into?: HTMLElement): void {
  const list = el("ul", null)
  for (const p of problems) list.append(el("li", null, p))
  showNotice("error", [el("p", "notice-title", "Check this first"), list], into)
}

export function showWarnings(title: string, warnings: string[]): void {
  const list = el("ul", null)
  for (const w of warnings) list.append(el("li", null, w))
  showNotice("warn", [el("p", "notice-title", title), list])
}

// A vault message as text, with each `quoted` command set as code.
function messageLine(className: string | null, text: string): HTMLElement {
  const line = el("p", className)
  text.split("`").forEach((part, i) => {
    if (part !== "") line.append(i % 2 === 1 ? el("code", null, part) : document.createTextNode(part))
  })
  return line
}

// What the browser refused, in plain words: a passkey prompt cancelled or
// timed out (the common one), or a new passkey on a device that already
// holds one for this account (InvalidStateError, as a second passkey added
// on the same device meets). Null for anything else.
export function browserRefusalWords(error: unknown): { title: string; say: string } | null {
  const name = error instanceof DOMException || error instanceof Error ? error.name : null
  if (name === "InvalidStateError") return { title: "This device already has a passkey for your account.", say: "Add the new one on another device or a security key instead. Nothing was changed." }
  if (error instanceof DOMException || name === "NotAllowedError") return { title: "The passkey check did not finish.", say: "It was cancelled or timed out. Nothing was changed; try again when you are ready." }
  return null
}

// The vault's own message and next step, or a plain explanation of what the
// browser refused.
export function showError(error: unknown, into?: HTMLElement): void {
  if (error instanceof VaultFailure) {
    const lines = [messageLine("notice-title", error.body.message)]
    const next = error.body.next
    if (next?.say) lines.push(messageLine(null, next.say))
    const url = next?.url ? safeUrl(next.url) : null
    if (url) {
      const link = el("a", "button secondary", "Continue") as HTMLAnchorElement
      link.href = url
      lines.push(link)
    }
    if (next?.command) {
      const p = el("p", null, "Or run ")
      p.append(el("code", null, next.command))
      lines.push(p)
    }
    showNotice("error", lines, into)
    return
  }
  const refused = browserRefusalWords(error)
  if (refused !== null) {
    showNotice("error", [el("p", "notice-title", refused.title), el("p", null, refused.say)], into)
    return
  }
  showNotice("error", [el("p", "notice-title", error instanceof Error ? error.message : "Something went wrong."), el("p", null, "Reload the page and try again.")], into)
}

// Runs one action with its button disabled and labelled as waiting, and
// shows any failure, in `into` when given. Returns whether it succeeded. The
// button gets its own children back afterwards, icon included, not just its
// text.
export async function withBusy(button: HTMLButtonElement, waiting: string, action: () => Promise<void>, into?: HTMLElement): Promise<boolean> {
  const label = Array.from(button.childNodes)
  button.disabled = true
  button.setAttribute("aria-busy", "true")
  button.textContent = waiting
  clearNotice(into)
  try {
    await action()
    return true
  } catch (error) {
    showError(error, into)
    return false
  } finally {
    button.replaceChildren(...label)
    button.removeAttribute("aria-busy")
    button.disabled = false
  }
}

export function inputValue(selector: string, root: ParentNode = document): string {
  return find<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(selector, root)?.value ?? ""
}
