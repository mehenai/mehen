// The ask card (browser entry): what a human was asked, what to check, when
// the link expires, "Open in vault" through the host, and the ask's live
// state from vault_ask_state. It shows state and opens the link; it never
// approves, declines or waits on anything itself.

import { Bridge, type CallToolResult } from "./bridge.ts"
import { type AskCardView, type AskState, type AskView, STATE_LABELS, STATE_TONES, askCardView, followAsk, isExpired, modelContext, relativeExpiry } from "./ask-card-logic.ts"
import { applyHostContext, el, footer, openControl } from "./card-dom.ts"

const TICK_MS = 30_000
const CALL_TIMEOUT_MS = 60_000

const bridge = new Bridge({ name: "mehen-ask-card", version: "1.0.0" })
const root = document.getElementById("card") as HTMLElement
const timers = new Set<ReturnType<typeof setTimeout>>()
let generation = 0
let ticker: ReturnType<typeof setInterval> | null = null

type Row = { view: AskView; state: AskState; expiresAt: string | null; message: string | null; liveStopped: boolean; update(): void }

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

function expiryText(expiresAt: string): string {
  return relativeExpiry(expiresAt, new Date()) ?? "unknown"
}

function checkNodes(view: AskView): Node[] {
  if (!view.check) return []
  const lead = view.check.lead.charAt(0).toUpperCase() + view.check.lead.slice(1)
  return [document.createTextNode(lead), el("strong", { class: "value", text: view.check.value }), document.createTextNode(view.check.tail)]
}

function badge(): HTMLElement {
  return el("span", { class: "badge", attrs: { role: "status", "aria-live": "polite" } })
}

function row(view: AskView, compact: boolean, note: string | null = null): { row: Row; node: HTMLElement } {
  const state: Row = { view, state: "waiting", expiresAt: view.expiresAt, message: null, liveStopped: false, update: () => undefined }
  const stateBadge = badge()
  const expiry = el("span")
  const message = el("p", { class: "message" })
  const live = el("p", { class: "live", text: "Live updates stopped; ask the agent to check on it." })
  const actions = openControl(bridge, view.url, view.openable, compact ? "secondary" : "primary")
  let node: HTMLElement
  if (compact) {
    const meta = el("p", { class: "meta" }, [...checkNodes(view), view.check && view.expiresAt ? " · " : null, view.expiresAt ? el("span", {}, ["Expires ", expiry]) : null])
    node = el("li", { class: "ask" }, [
      el("div", { class: "head" }, [el("h2", { text: view.title }), stateBadge]),
      el("p", { class: "what", text: view.what }),
      view.check || view.expiresAt ? meta : null,
      message,
      actions,
      live,
    ])
  } else {
    const facts: Node[] = []
    const fact = (label: string, value: Node[]) => facts.push(el("dt", { text: label }), el("dd", {}, value))
    if (view.check) fact("Check", checkNodes(view))
    if (view.account) fact("Account", [document.createTextNode(view.account)])
    if (view.askedBy) fact("Asked by", [document.createTextNode(view.askedBy)])
    if (view.expiresAt) fact("Expires", [expiry])
    node = el("div", {}, [
      el("div", { class: "head" }, [el("div", {}, [el("p", { class: "eyebrow", text: "Mehen · human needed" }), el("h1", { text: view.title })]), stateBadge]),
      el("p", { class: "what", text: view.what }),
      note ? el("p", { class: "note", text: note }) : null,
      facts.length ? el("dl", { class: "facts" }, facts) : null,
      message,
      actions,
      live,
    ])
  }
  state.update = () => {
    stateBadge.textContent = STATE_LABELS[state.state]
    stateBadge.dataset.tone = STATE_TONES[state.state]
    if (state.expiresAt) {
      const text = expiryText(state.expiresAt)
      expiry.textContent = text
      expiry.className = text === "expired" ? "expired" : ""
    }
    message.textContent = state.message ?? ""
    message.hidden = state.message === null
    actions.hidden = state.state !== "waiting"
    live.hidden = !state.liveStopped || state.state !== "waiting"
  }
  state.update()
  return { row: state, node }
}

function follow(rows: Row[], current: number): void {
  if (!bridge.capabilities.serverTools) return
  const settled: { id: string; state: AskState }[] = []
  for (const r of rows) {
    if (!r.view.live) continue
    void followAsk({
      id: r.view.id,
      workspace: r.view.workspace,
      call: (args) => bridge.callTool("vault_ask_state", args, CALL_TIMEOUT_MS),
      sleep,
      now: () => Date.now(),
      expired: () => isExpired(r.expiresAt, new Date()),
      stopped: () => current !== generation || bridge.closed,
      onRead: (read) => {
        if (current !== generation) return
        r.state = read.state
        if (read.expiresAt) r.expiresAt = read.expiresAt
        r.message = read.state === "waiting" ? null : read.message
        r.update()
      },
    }).then((end) => {
      if (current !== generation) return
      if (end.end === "errors") r.liveStopped = true
      if (end.end === "expired" && r.state === "waiting") r.state = "expired"
      r.update()
      if (end.end !== "settled") return
      settled.push({ id: r.view.id, state: end.state })
      const context = modelContext(settled)
      if (context) bridge.updateModelContext({ structuredContent: context }).catch(() => undefined)
    })
  }
}

function tick(rows: Row[]): void {
  const now = new Date()
  for (const r of rows) {
    if (r.state === "waiting" && isExpired(r.expiresAt, now)) r.state = "expired"
    r.update()
  }
}

function render(view: AskCardView): void {
  stop()
  const current = generation
  if (view.kind === "none") {
    root.replaceChildren()
    bridge.watchSize()
    return
  }
  let rows: Row[]
  if (view.kind === "single") {
    const built = row(view.ask, false, view.note)
    rows = [built.row]
    root.replaceChildren(el("article", { class: "card", attrs: { "aria-label": view.ask.title } }, [built.node, footer()]))
  } else {
    const built = view.asks.map((a) => row(a, true))
    rows = built.map((b) => b.row)
    root.replaceChildren(
      el("article", { class: "card", attrs: { "aria-label": "Open asks" } }, [
        el("div", {}, [el("p", { class: "eyebrow", text: "Mehen · open asks" }), el("h1", { text: `${view.asks.length + view.more} asks are waiting on a human` })]),
        el("ul", { class: "asks" }, built.map((b) => b.node)),
        view.more > 0 ? el("p", { class: "more", text: `and ${view.more} more` }) : null,
        footer(),
      ]),
    )
  }
  tick(rows)
  bridge.watchSize()
  ticker = setInterval(() => tick(rows), TICK_MS)
  follow(rows, current)
}

bridge.onHostContext(applyHostContext)
bridge.onToolResult((result: CallToolResult) => render(askCardView(result)))
bridge.onToolCancelled(() => render({ kind: "none" }))
bridge.onTeardown(stop)
bridge.connect().catch(() => undefined)
