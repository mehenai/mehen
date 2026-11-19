// Small wires every page gets: a Copy button beside a code value, a
// countdown ring driven from its expiry (the maths is in countdown.ts), and
// times in the reader's own zone.

import { type RingState, ringOffset, ringState, ringText } from "./countdown.ts"
import { all } from "./dom.ts"

function applyRing(ring: SVGSVGElement, state: RingState): void {
  const fill = ring.querySelector<SVGCircleElement>(".ring-fill")
  fill?.setAttribute("stroke-dashoffset", String(ringOffset(state.fraction)))
  ring.classList.toggle("warn", state.tone === "warn")
  ring.classList.toggle("danger", state.tone === "danger")
  const text = ring.parentElement?.querySelector<HTMLElement>("[data-ring-text]")
  if (text) text.textContent = state.expired ? "ran out" : `${ringText(state.left)} left`
}

// Every <svg data-ring data-expires data-total> under `root` ticks once a
// second and dispatches `vault:expired` on itself (bubbling) once at zero.
// A ring taken off the page (a list redrawn in place) stops ticking.
export function wireRings(now: () => number = Date.now, root: ParentNode = document): void {
  const rings = all<SVGSVGElement>("[data-ring]", root)
  if (rings.length === 0) return
  const fired = new WeakSet<SVGSVGElement>()
  const tick = () => {
    let live = 0
    for (const ring of rings) {
      if (!ring.isConnected) continue
      const expiresAt = Date.parse(ring.dataset.expires ?? "")
      const total = Number(ring.dataset.total ?? "0")
      if (Number.isNaN(expiresAt)) continue
      const state = ringState(expiresAt, total, now())
      applyRing(ring, state)
      if (state.expired) {
        if (!fired.has(ring)) {
          fired.add(ring)
          ring.dispatchEvent(new CustomEvent("vault:expired", { bubbles: true }))
        }
      } else live++
    }
    if (live > 0) setTimeout(tick, 1000)
  }
  tick()
}

// Every <time datetime> the server wrote (timeTag in components.ts) reads
// in this browser's own time zone; the UTC words stay in its title.
export function localTimeWords(at: Date): string {
  const day = at.toLocaleDateString("en-GB", { day: "numeric", month: "short" })
  const year = at.getFullYear() !== new Date().getFullYear() ? ` ${at.getFullYear()}` : ""
  const time = at.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })
  return `${day}${year}, ${time}`
}

export function wireTimes(root: ParentNode = document): void {
  for (const node of all<HTMLTimeElement>("time[datetime]", root)) {
    const at = new Date(node.dateTime)
    if (Number.isNaN(at.getTime())) continue
    if (!node.title) node.title = node.textContent ?? ""
    node.textContent = localTimeWords(at)
  }
}

export const COPIED_FOR_MS = 1200

// A <button data-copy> copies the text of the <code> beside it and reads
// "Copied" for a moment.
export function wireCopy(): void {
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
