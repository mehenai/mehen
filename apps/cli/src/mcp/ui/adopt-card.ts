// The adopt card (browser entry): a vault_adopt_scan report or a
// vault_adopt_status batch as a readable summary. While a batch is open it
// follows the batch through vault_ask_state and, once it settles, reads the
// batch again with vault_adopt_status; it approves and stores nothing.

import { Bridge, type CallToolResult } from "./bridge.ts"
import { ADOPTION_LABELS, type AdoptCardView, type AdoptionState, type ScanView, type StatusView, adoptCardView, adoptionStateFor, itemsText } from "./adopt-card-logic.ts"
import { followAsk, isExpired, isLiveId, relativeExpiry } from "./ask-card-logic.ts"
import { applyHostContext, el, footer, openControl } from "./card-dom.ts"

const CALL_TIMEOUT_MS = 60_000
const TICK_MS = 30_000

const bridge = new Bridge({ name: "mehen-adopt-card", version: "1.0.0" })
const root = document.getElementById("card") as HTMLElement
const timers = new Set<ReturnType<typeof setTimeout>>()
let generation = 0
let ticker: ReturnType<typeof setInterval> | null = null
let toolArgs: Record<string, unknown> = {}

const TONES: Record<AdoptionState, string> = { open: "waiting", approved: "ok", cancelled: "quiet", expired: "quiet" }

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      timers.delete(timer)
      resolve()
    }, ms)
    timers.add(timer)
  })
}

function stop(): void {
  generation++
  if (ticker !== null) clearInterval(ticker)
  ticker = null
  for (const timer of timers) clearTimeout(timer)
  timers.clear()
}

function heading(eyebrow: string, title: string, side: Node | null): HTMLElement {
  return el("div", { class: "head" }, [el("div", {}, [el("p", { class: "eyebrow", text: eyebrow }), el("h1", { text: title })]), side])
}

// A path that keeps its end in view when it is cut.
function path(text: string): HTMLElement {
  return el("span", { class: "path", attrs: { title: text } }, [el("bdi", { text })])
}

function scanCard(view: ScanView): HTMLElement {
  const secrets = view.figures.find((f) => f.label === "secrets")?.value ?? 0
  const title = secrets === 0 ? "No secrets found to move" : `${secrets} secret${secrets === 1 ? "" : "s"} could move into the vault`
  const folders = view.folders.map((f) =>
    el("li", {}, [path(f.folder), el("span", { class: "side" }, [el("span", { text: `${f.secrets} secret${f.secrets === 1 ? "" : "s"}${f.config ? ` · ${f.config} config` : ""}` }), f.home ? el("span", { class: "home", text: f.home }) : null])]),
  )
  return el("article", { class: "card", attrs: { "aria-label": "Adoption scan" } }, [
    heading("Mehen · adoption scan", title, null),
    el(
      "ul",
      { class: "figures" },
      view.figures.map((f, i) => el("li", { class: i === 1 ? "figure lead" : "figure" }, [el("b", { text: String(f.value) }), el("span", { text: f.label })])),
    ),
    folders.length ? el("h2", { class: "section", text: "Folders, most secrets first" }) : null,
    folders.length ? el("ul", { class: "rows" }, folders) : null,
    view.moreFolders > 0 ? el("p", { class: "more", text: `and ${view.moreFolders} more` }) : null,
    view.unread.length ? el("h2", { class: "section", text: "Could not be read" }) : null,
    view.unread.length ? el("ul", { class: "lines" }, view.unread.map((line) => el("li", { text: line }))) : null,
    view.moreUnread > 0 ? el("p", { class: "more", text: `and ${view.moreUnread} more folders` }) : null,
    view.skipped > 0 ? el("p", { class: "more", text: `${view.skipped} file${view.skipped === 1 ? " was" : "s were"} skipped.` }) : null,
    view.next ? el("h2", { class: "section", text: "Next, at a terminal" }) : null,
    view.next ? el("pre", { class: "command", text: view.next }) : null,
    el("p", { class: "footer" }, [el("span", { text: "Names, kinds and folders only; no value leaves this machine in a scan." })]),
  ])
}

function statusCard(view: StatusView, current: number): HTMLElement {
  let state = view.state
  const stateBadge = el("span", { class: "badge", attrs: { role: "status", "aria-live": "polite" } })
  const expiry = el("span")
  const actions = view.url ? openControl(bridge, view.url, true, "primary") : null
  const live = el("p", { class: "live", text: "Live updates stopped; ask the agent to check on it." })
  live.hidden = true
  const update = () => {
    if (state === "open" && isExpired(view.expiresAt, new Date())) state = "expired"
    stateBadge.textContent = ADOPTION_LABELS[state]
    stateBadge.dataset.tone = TONES[state]
    if (view.expiresAt) {
      const text = relativeExpiry(view.expiresAt, new Date()) ?? "unknown"
      expiry.textContent = text
      expiry.className = text === "expired" ? "expired" : ""
    }
    if (actions) actions.hidden = state !== "open"
    if (state !== "open") live.hidden = true
  }
  const facts: Node[] = [el("dt", { text: "Batch" }), el("dd", {}, [el("span", { class: "value", text: view.adoption })])]
  for (const m of view.machines) facts.push(el("dt", { text: "From" }), el("dd", { text: `${m.name}, ${itemsText(m.items)}` }))
  if (view.expiresAt && view.state === "open") facts.push(el("dt", { text: "Expires" }), el("dd", {}, [expiry]))
  const card = el("article", { class: "card", attrs: { "aria-label": "Adoption batch" } }, [
    heading("Mehen · adoption", view.state === "approved" ? "Adopted credentials" : "Review adopted credentials", stateBadge),
    el("dl", { class: "facts" }, facts),
    view.created.length ? el("h2", { class: "section", text: `Created (${view.created.length + view.moreCreated})` }) : null,
    view.created.length ? el("ul", { class: "rows" }, view.created.map((slug) => el("li", {}, [path(slug)]))) : null,
    view.moreCreated > 0 ? el("p", { class: "more", text: `and ${view.moreCreated} more` }) : null,
    view.refused.length ? el("h2", { class: "section", text: `Refused (${view.refused.length + view.moreRefused})` }) : null,
    view.refused.length ? el("ul", { class: "lines" }, view.refused.map((r) => el("li", {}, [el("span", { class: "value", text: r.ref }), el("span", { class: "reason", text: r.reason ? `: ${r.reason}` : "" })]))) : null,
    view.moreRefused > 0 ? el("p", { class: "more", text: `and ${view.moreRefused} more` }) : null,
    actions,
    live,
    footer(),
  ])
  update()
  ticker = setInterval(update, TICK_MS)
  if (view.state === "open" && bridge.capabilities.serverTools && isLiveId(view.adoption)) {
    const workspace = typeof toolArgs.workspace === "string" ? toolArgs.workspace : null
    void followAsk({
      id: view.adoption,
      workspace,
      call: (args) => bridge.callTool("vault_ask_state", args, CALL_TIMEOUT_MS),
      sleep,
      now: () => Date.now(),
      expired: () => isExpired(view.expiresAt, new Date()),
      stopped: () => current !== generation || bridge.closed,
      onRead: (read) => {
        if (current !== generation) return
        state = adoptionStateFor(read.state) ?? state
        update()
      },
    }).then(async (end) => {
      if (current !== generation) return
      if (end.end === "errors") live.hidden = false
      update()
      if (end.end !== "settled") return
      bridge.updateModelContext({ structuredContent: { ask: view.adoption, state: end.state } }).catch(() => undefined)
      // The settled batch as the vault now reports it: created and refused items.
      const fresh = await bridge.callTool("vault_adopt_status", { adoption: view.adoption, ...(workspace ? { workspace } : {}) }, CALL_TIMEOUT_MS).catch(() => null)
      if (fresh && current === generation) render(adoptCardView(fresh))
    })
  }
  return card
}

function render(view: AdoptCardView): void {
  stop()
  const current = generation
  if (view.kind === "none") root.replaceChildren()
  else if (view.kind === "scan") root.replaceChildren(scanCard(view))
  else root.replaceChildren(statusCard(view, current))
  bridge.watchSize()
}

bridge.onHostContext(applyHostContext)
bridge.onToolInput((args) => {
  toolArgs = args
})
bridge.onToolResult((result: CallToolResult) => render(adoptCardView(result)))
bridge.onToolCancelled(() => render({ kind: "none" }))
bridge.onTeardown(stop)
bridge.connect().catch(() => undefined)
