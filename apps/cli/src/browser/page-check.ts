// The check mehen fill runs in the page before it types (design 3, "The
// check"). It runs in the `mehen-fill` isolated world of the field's own
// frame: that world shares the page's DOM but has its own globals and its
// own prototypes, so page script cannot patch them. A named element (an
// <img name="querySelectorAll">, a <form name="activeElement">) can still
// shadow a document's or a form's property in a browser that exposes named
// properties to isolated worlds, so each function captures the document and
// shadow-root methods and getters it calls from this world's prototypes on
// entry and calls them through those. Anything else a named property
// shadows fails closed: a wrong kind, or an exception, which is never typed
// past. The last check and the typing are one function call, so one task: a
// navigation cannot commit in between, so the origin checked is the origin
// typed into. Only the page's focus handlers run inside it, so the field's
// type and state are checked again once it has the focus.

import type { FillInput } from "@mehen/protocol/kinds"
import { CdpCallError, type CdpConnection, type CdpEvent } from "./cdp.ts"

export const WORLD_NAME = "mehen-fill"

// The document and shadow-root methods and getters the check calls, taken
// from this world's prototypes as the function starts.
const CAPTURE = `
  const getter = (proto, name) => Object.getOwnPropertyDescriptor(proto, name).get
  const dom = {
    query: (root, css) => (root === document ? Document.prototype.querySelectorAll : DocumentFragment.prototype.querySelectorAll).call(root, css),
    shadowOf: ((get) => (element) => get.call(element))(getter(Element.prototype, "shadowRoot")),
    fromPoint: ((ofDocument, ofShadow) => (root, x, y) => (root === document ? ofDocument : ofShadow).call(root, x, y))(Document.prototype.elementFromPoint, ShadowRoot.prototype.elementFromPoint),
    activeOf: ((ofDocument, ofShadow) => (root) => (root === document ? ofDocument : ofShadow).call(root))(getter(Document.prototype, "activeElement"), getter(ShadowRoot.prototype, "activeElement")),
    insertText: ((exec) => (value) => exec.call(document, "insertText", false, value))(Document.prototype.execCommand),
  }
`

// The one element a selector names: each ` >>> ` hop steps into an open
// shadow root and must match exactly once there too. Answers the element,
// or "none", "many", "closed" (no open shadow root at a hop) or "invalid".
const RESOLVE = `
  const hops = selector.split(" >>> ")
  let root = document
  let found = null
  for (let i = 0; i < hops.length; i++) {
    let list
    try { list = dom.query(root, hops[i]) } catch (e) { return "invalid" }
    if (list.length === 0) return "none"
    if (list.length > 1) return "many"
    found = list[0]
    if (i < hops.length - 1) {
      root = dom.shadowOf(found)
      if (!root) return "closed"
    }
  }
  return found
`

// The focused element, through open shadow roots.
const ACTIVE = `
  let active = dom.activeOf(document)
  while (active && dom.shadowOf(active) && dom.activeOf(dom.shadowOf(active))) active = dom.activeOf(dom.shadowOf(active))
`

export const RESOLVE_FIELD = `function (selector) {${CAPTURE}${RESOLVE}}`

// Is this element still the one the selector names, in a frame whose origin
// and every ancestor's are `origin`, as the browser (`ancestors`, from CDP)
// and the frame itself (location.ancestorOrigins) both say?
const SAME_PAGE = `
  const el = this
  if (!el.isConnected) return { code: "page_changed", reason: "the field is no longer in the page" }
  const again = (function () {${RESOLVE}})()
  if (again !== el) return { code: "page_changed", reason: "the selector no longer names the same field" }
  if (location.origin !== origin) return { code: "frame_origin_mismatch", reason: "the field's frame is now " + (location.origin === "null" ? "an opaque origin" : "another origin") }
  const world = location.ancestorOrigins ? Array.from(location.ancestorOrigins) : null
  if (world === null) return { code: "frame_origin_mismatch", reason: "the frame does not list its ancestors" }
  if (world.length !== ancestors.length || world.some((entry, i) => entry !== ancestors[i])) return { code: "frame_origin_mismatch", reason: "the browser and the page disagree about the frame's ancestors" }
  if (world.some((entry) => entry !== origin)) return { code: "frame_origin_mismatch", reason: "an ancestor of the field's frame has another origin" }
`

// The check, then (when `value` is a string) focus, the activeElement check
// and execCommand("insertText"), all in this one call.
export const CHECK_FIELD = `function (selector, origin, ancestors, input, value) {${CAPTURE}${SAME_PAGE}
  const tag = el.localName
  const type = tag === "input" ? el.type : null
  const tokens = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\\s+/).filter(Boolean)
  let kind = false
  if (input === "password") kind = type === "password" && !tokens.includes("new-password")
  else if (input === "username") kind = (type === "text" || type === "email") && (tokens.includes("username") || tokens.includes("email") || /user|email|login/i.test((el.getAttribute("name") || "") + " " + (el.id || "")))
  else if (input === "one-time-code") kind = (type === "text" || type === "tel" || type === "number" || type === "password") && (tokens.includes("one-time-code") || el.inputMode === "numeric" || (el.maxLength >= 6 && el.maxLength <= 8))
  else if (input === "secret") kind = type === "text" || type === "password" || tag === "textarea"
  if (!kind) return { code: "field_kind_mismatch", reason: tag === "input" ? "it is an input of type " + type : "it is not an input or a text area" }
  if (el.disabled || el.readOnly) return { code: "field_hidden", reason: "it is disabled or read-only" }
  if (typeof el.checkVisibility !== "function" || !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return { code: "field_hidden", reason: "it is not visible" }
  el.scrollIntoView({ block: "center", inline: "center" })
  const box = el.getBoundingClientRect()
  if (box.width < 1 || box.height < 1) return { code: "field_hidden", reason: "it has no size" }
  const x = box.left + box.width / 2, y = box.top + box.height / 2
  let hit = dom.fromPoint(document, x, y)
  while (hit && hit !== el && dom.shadowOf(hit)) {
    const inner = dom.fromPoint(dom.shadowOf(hit), x, y)
    if (!inner || inner === hit) break
    hit = inner
  }
  if (hit !== el && !(hit && el.contains(hit))) return { code: "field_hidden", reason: "another element covers it" }
  if (typeof value !== "string") return { code: "ok" }
  el.focus()${ACTIVE}
  if (active !== el) return { code: "field_hidden", reason: "it did not take the focus" }
  if (tag === "input" && el.type !== type) return { code: "field_kind_mismatch", reason: "its type changed to " + el.type + " when it took the focus" }
  if (el.disabled || el.readOnly) return { code: "field_hidden", reason: "it became disabled or read-only when it took the focus" }
  el.select()
  if (!dom.insertText(value)) return { code: "field_hidden", reason: "it did not take the typing" }
  return { code: "typed" }
}`

// Just before the trusted Enter of --submit: the same page, and the field
// focused again so the Enter goes to it.
export const BEFORE_ENTER = `function (selector, origin, ancestors) {${CAPTURE}${SAME_PAGE}
  el.focus()${ACTIVE}
  if (active !== el) return { code: "page_changed", reason: "the field lost the focus" }
  return { code: "ok" }
}`

export const FIELD_PRESENT = "function () { return this.isConnected }"

// Empties the field through the native value setter of this world's own
// prototypes, then tells the page with an input event.
export const CLEAR_FIELD = `function () {
  const proto = this.localName === "textarea" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype
  Object.getOwnPropertyDescriptor(proto, "value").set.call(this, "")
  this.dispatchEvent(new Event("input", { bubbles: true }))
  return this.value === ""
}`

export type FrameInfo = { id: string; parentId: string | null; url: string; securityOrigin: string; sessionId: string }

type FrameTree = { frame: { id: string; parentId?: string; url: string; securityOrigin?: string }; childFrames?: FrameTree[] }
type TargetInfo = { targetId: string; type: string }

// Every session that shows a part of the page: the page's own, then each
// out-of-process frame's (Target.setAutoAttach, which reports the frames
// already there before it answers), recursively.
async function frameSessions(connection: CdpConnection, pageSession: string): Promise<string[]> {
  const sessions = [pageSession]
  for (let i = 0; i < sessions.length; i++) {
    const parent = sessions[i] as string
    const attached: string[] = []
    const stop = connection.onEvent((event: CdpEvent) => {
      if (event.method !== "Target.attachedToTarget" || event.sessionId !== parent) return
      const info = event.params.targetInfo as TargetInfo | undefined
      if (info?.type === "iframe" && typeof event.params.sessionId === "string") attached.push(event.params.sessionId)
    })
    try {
      await connection.send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true, filter: [{ type: "iframe", exclude: false }] }, { sessionId: parent })
    } finally {
      stop()
    }
    for (const session of attached) if (!sessions.includes(session)) sessions.push(session)
  }
  return sessions
}

// Every frame of the page, keyed by id, with the session that owns it. An
// out-of-process frame is owned by its own session, which is listed after
// the session of its parent, so it overrides any entry the parent made.
export async function pageFrames(connection: CdpConnection, pageSession: string): Promise<Map<string, FrameInfo>> {
  const frames = new Map<string, FrameInfo>()
  for (const sessionId of await frameSessions(connection, pageSession)) {
    let tree: FrameTree
    try {
      tree = (await connection.send<{ frameTree: FrameTree }>("Page.getFrameTree", {}, { sessionId })).frameTree
    } catch (error) {
      if (error instanceof CdpCallError) continue
      throw error
    }
    const walk = (node: FrameTree) => {
      const { frame } = node
      frames.set(frame.id, { id: frame.id, parentId: frame.parentId ?? null, url: frame.url, securityOrigin: frame.securityOrigin ?? "", sessionId })
      for (const child of node.childFrames ?? []) walk(child)
    }
    walk(tree)
  }
  return frames
}

// The security origins of a frame's ancestors, nearest first, as the
// browser reports them; null when one of them is not among the frames.
export function frameAncestors(frames: Map<string, FrameInfo>, frameId: string): string[] | null {
  const ancestors: string[] = []
  let parent = frames.get(frameId)?.parentId ?? null
  while (parent !== null) {
    const frame = frames.get(parent)
    if (!frame || ancestors.length > 64) return null
    ancestors.push(frame.securityOrigin)
    parent = frame.parentId
  }
  return ancestors
}

export type LocatedField = { frame: FrameInfo; sessionId: string; contextId: number; objectId: string }
export type Located = { field: LocatedField } | { none: { closed: boolean } } | { many: number } | { invalid: true }

type RemoteObject = { type: string; subtype?: string; value?: unknown; objectId?: string }
type CallResult = { result: RemoteObject; exceptionDetails?: unknown }

// The one element the selector names across every frame of the page.
export async function locateField(connection: CdpConnection, frames: Map<string, FrameInfo>, selector: string): Promise<Located> {
  const found: LocatedField[] = []
  let closed = false
  for (const frame of frames.values()) {
    let contextId: number
    try {
      contextId = (await connection.send<{ executionContextId: number }>("Page.createIsolatedWorld", { frameId: frame.id, worldName: WORLD_NAME, grantUniveralAccess: false }, { sessionId: frame.sessionId })).executionContextId
    } catch (error) {
      if (error instanceof CdpCallError) continue
      throw error
    }
    let answer: CallResult
    try {
      answer = await connection.send<CallResult>("Runtime.callFunctionOn", { functionDeclaration: RESOLVE_FIELD, executionContextId: contextId, arguments: [{ value: selector }], returnByValue: false }, { sessionId: frame.sessionId })
    } catch (error) {
      if (error instanceof CdpCallError) continue
      throw error
    }
    if (answer.exceptionDetails) continue
    const { result } = answer
    if (result.type === "object" && result.subtype === "node" && typeof result.objectId === "string") found.push({ frame, sessionId: frame.sessionId, contextId, objectId: result.objectId })
    else if (result.value === "invalid") return { invalid: true }
    else if (result.value === "many") return { many: 2 }
    else if (result.value === "closed") closed = true
  }
  if (found.length === 1) return { field: found[0] as LocatedField }
  if (found.length > 1) return { many: found.length }
  return { none: { closed } }
}

export type PageVerdict = { code: string; reason?: string }

// Runs one of the functions above on the field. A CDP refusal (the context
// or the object is gone) is page_changed; an exception in the page is never
// passed on, since its text is the page's.
export async function onField(connection: CdpConnection, field: LocatedField, functionDeclaration: string, args: unknown[]): Promise<PageVerdict> {
  let answer: CallResult
  try {
    answer = await connection.send<CallResult>("Runtime.callFunctionOn", { functionDeclaration, objectId: field.objectId, arguments: args.map((value) => ({ value })), returnByValue: true }, { sessionId: field.sessionId })
  } catch (error) {
    if (error instanceof CdpCallError) return { code: "page_changed", reason: "the field's frame went away" }
    throw error
  }
  if (answer.exceptionDetails) return { code: "page_failed" }
  const value = answer.result.value
  if (typeof value === "boolean") return { code: value ? "ok" : "false" }
  if (typeof value === "object" && value !== null && typeof (value as PageVerdict).code === "string") {
    const verdict = value as PageVerdict
    return typeof verdict.reason === "string" ? { code: verdict.code, reason: verdict.reason } : { code: verdict.code }
  }
  return { code: "page_failed" }
}

export type FieldCheck = { selector: string; origin: string; ancestors: string[]; input: FillInput }

export function checkField(connection: CdpConnection, field: LocatedField, check: FieldCheck, value: string | null): Promise<PageVerdict> {
  return onField(connection, field, CHECK_FIELD, [check.selector, check.origin, check.ancestors, check.input, value])
}
