// A small document for running the real browser handlers (ui/client/pages)
// in the test Worker, which has no DOM. It parses the server-rendered page
// the handlers wire, answers the selectors they use (compound attribute,
// id, class and tag selectors, :checked, descendant and comma lists), keeps
// form state (value, checked, disabled, hidden), dispatches bubbling events,
// keeps the document's focused element and records navigation. Just enough for those handlers, nothing more.

type Listener = (event: MiniEvent) => void

export class MiniEvent {
  readonly type: string
  readonly bubbles: boolean
  defaultPrevented = false
  target: MiniElement | null = null
  constructor(type: string, init: { bubbles?: boolean } = {}) {
    this.type = type
    this.bubbles = init.bubbles ?? false
  }
  preventDefault(): void {
    this.defaultPrevented = true
  }
}

export class MiniText {
  readonly nodeType = 3
  parent: MiniElement | null = null
  constructor(public text: string) {}
  get textContent(): string {
    return this.text
  }
}

type MiniNode = MiniElement | MiniText

const VOID = new Set(["input", "br", "img", "meta", "link", "hr", "source", "path", "circle", "rect", "line", "polyline", "polygon", "ellipse"])

function decode(text: string): string {
  return text.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#96;", "`").replaceAll("&amp;", "&")
}

function camel(name: string): string {
  return name.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase())
}

export class MiniElement {
  readonly nodeType = 1
  readonly tagName: string
  readonly attributes = new Map<string, string>()
  children: MiniNode[] = []
  parent: MiniElement | null = null
  private listeners = new Map<string, Listener[]>()
  private ownValue: string | null = null
  private ownChecked: boolean | null = null
  // On the document: the element focus() last moved to.
  activeElement: MiniElement | null = null

  constructor(tag: string) {
    this.tagName = tag.toUpperCase()
  }

  get localName(): string {
    return this.tagName.toLowerCase()
  }
  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null
  }
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, String(value))
  }
  removeAttribute(name: string): void {
    this.attributes.delete(name)
  }
  hasAttribute(name: string): boolean {
    return this.attributes.has(name)
  }
  private flag(name: string, on: boolean): void {
    if (on) this.attributes.set(name, "")
    else this.attributes.delete(name)
  }
  get hidden(): boolean {
    return this.attributes.has("hidden")
  }
  set hidden(on: boolean) {
    this.flag("hidden", on)
  }
  get disabled(): boolean {
    return this.attributes.has("disabled")
  }
  set disabled(on: boolean) {
    this.flag("disabled", on)
  }
  get checked(): boolean {
    return this.ownChecked ?? this.attributes.has("checked")
  }
  set checked(on: boolean) {
    this.ownChecked = on
    if (on && this.getAttribute("type") === "radio") {
      const name = this.getAttribute("name")
      for (const other of root(this).querySelectorAll(`input[name="${name}"]`)) if (other !== this) other.ownChecked = false
    }
  }
  get value(): string {
    if (this.ownValue !== null) return this.ownValue
    if (this.localName === "select") {
      const options = this.querySelectorAll("option")
      return (options.find((o) => o.hasAttribute("selected")) ?? options[0])?.getAttribute("value") ?? ""
    }
    if (this.localName === "textarea") return this.textContent
    return this.getAttribute("value") ?? (this.getAttribute("type") === "checkbox" || this.getAttribute("type") === "radio" ? "on" : "")
  }
  set value(v: string) {
    this.ownValue = v
  }
  // A select's options and its chosen one. An option is selected when its
  // select's value is the option's own, and selecting it makes that so.
  get options(): MiniElement[] {
    return this.querySelectorAll("option")
  }
  get selectedOptions(): MiniElement[] {
    const value = this.value
    return this.options.filter((o) => (o.getAttribute("value") ?? "") === value).slice(0, 1)
  }
  get selected(): boolean {
    return this.closest("select")?.selectedOptions[0] === this
  }
  set selected(on: boolean) {
    const select = this.closest("select")
    if (on && select !== null) select.value = this.getAttribute("value") ?? ""
  }
  get className(): string {
    return this.getAttribute("class") ?? ""
  }
  set className(v: string) {
    this.setAttribute("class", v)
  }
  get classList() {
    const read = () => new Set(this.className.split(/\s+/).filter(Boolean))
    const write = (set: Set<string>) => (this.className = [...set].join(" "))
    return {
      contains: (c: string) => read().has(c),
      add: (...cs: string[]) => write(new Set([...read(), ...cs])),
      remove: (...cs: string[]) => write(new Set([...read()].filter((c) => !cs.includes(c)))),
      toggle: (c: string, on?: boolean) => {
        const set = read()
        const want = on ?? !set.has(c)
        if (want) set.add(c)
        else set.delete(c)
        write(set)
        return want
      },
    }
  }
  get dataset(): Record<string, string | undefined> {
    const out: Record<string, string | undefined> = {}
    for (const [k, v] of this.attributes) if (k.startsWith("data-")) out[camel(k.slice(5))] = v
    return new Proxy(out, { set: (_t, key, value) => (this.setAttribute(`data-${String(key).replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`, String(value)), true) })
  }
  get id(): string {
    return this.getAttribute("id") ?? ""
  }
  get textContent(): string {
    return this.children.map((c) => c.textContent).join("")
  }
  set textContent(text: string) {
    this.replaceChildren(new MiniText(text))
  }
  get childNodes(): MiniNode[] {
    return [...this.children]
  }
  get href(): string {
    return this.getAttribute("href") ?? ""
  }
  set href(v: string) {
    this.setAttribute("href", v)
  }
  set title(v: string) {
    this.setAttribute("title", v)
  }
  append(...nodes: (MiniNode | string)[]): void {
    for (const n of nodes) {
      const node = typeof n === "string" ? new MiniText(n) : n
      node.parent?.children.splice(node.parent.children.indexOf(node), 1)
      node.parent = this
      this.children.push(node)
    }
  }
  prepend(...nodes: (MiniNode | string)[]): void {
    const kept = this.children
    this.children = []
    this.append(...nodes)
    this.children.push(...kept)
  }
  appendChild(node: MiniNode): MiniNode {
    this.append(node)
    return node
  }
  replaceWith(node: MiniNode): void {
    const parent = this.parent
    if (parent === null) return
    node.parent?.children.splice(node.parent.children.indexOf(node), 1)
    parent.children.splice(parent.children.indexOf(this), 1, node)
    node.parent = parent
    this.parent = null
  }
  remove(): void {
    this.parent?.children.splice(this.parent.children.indexOf(this), 1)
    this.parent = null
  }
  replaceChildren(...nodes: (MiniNode | string)[]): void {
    for (const c of this.children) c.parent = null
    this.children = []
    this.append(...nodes)
  }
  addEventListener(type: string, listener: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener])
  }
  dispatchEvent(event: MiniEvent): boolean {
    event.target ??= this
    let at: MiniElement | null = this
    while (at) {
      for (const l of at.listeners.get(event.type) ?? []) l(event)
      if (!event.bubbles) break
      at = at.parent
    }
    return !event.defaultPrevented
  }
  click(): void {
    if (this.disabled) return
    if (this.getAttribute("type") === "checkbox") this.checked = !this.checked
    if (this.getAttribute("type") === "radio") this.checked = true
    this.dispatchEvent(new MiniEvent("click", { bubbles: true }))
    if (this.getAttribute("type") === "checkbox" || this.getAttribute("type") === "radio") this.dispatchEvent(new MiniEvent("change", { bubbles: true }))
  }
  scrollIntoView(): void {}
  focus(): void {
    root(this).activeElement = this
  }
  select(): void {}
  closest(selector: string): MiniElement | null {
    let at: MiniElement | null = this
    while (at) {
      if (matches(at, selector)) return at
      at = at.parent
    }
    return null
  }
  querySelectorAll(selector: string): MiniElement[] {
    const out: MiniElement[] = []
    const walk = (el: MiniElement) => {
      for (const c of el.children) {
        if (c instanceof MiniElement) {
          if (matches(c, selector)) out.push(c)
          walk(c)
        }
      }
    }
    walk(this)
    return out
  }
  querySelector(selector: string): MiniElement | null {
    return this.querySelectorAll(selector)[0] ?? null
  }
}

function root(el: MiniElement): MiniElement {
  let at = el
  while (at.parent) at = at.parent
  return at
}

type Compound = { tag: string | null; id: string | null; classes: string[]; attrs: { name: string; value: string | null }[]; checked: boolean }

function parseCompound(text: string): Compound {
  const c: Compound = { tag: null, id: null, classes: [], attrs: [], checked: false }
  let m: RegExpExecArray | null
  let at = 0
  const tag = /^[a-z][a-z0-9-]*/.exec(text)
  if (tag) {
    c.tag = tag[0]
    at = tag[0].length
  }
  const rest = /#([\w-]+)|\.([\w-]+)|\[([\w-]+)(?:="((?:[^"\\]|\\.)*)")?\]|(:checked)/g
  rest.lastIndex = at
  while ((m = rest.exec(text)) !== null) {
    if (m[1]) c.id = m[1]
    else if (m[2]) c.classes.push(m[2])
    else if (m[3]) c.attrs.push({ name: m[3], value: m[4] === undefined ? null : m[4].replace(/\\(.)/g, "$1") })
    else if (m[5]) c.checked = true
  }
  return c
}

// Splits on spaces outside brackets and quotes.
function parts(selector: string): string[] {
  const out: string[] = []
  let cur = "", depth = 0, quote = false
  for (const ch of selector.trim()) {
    if (ch === '"') quote = !quote
    if (!quote && ch === "[") depth++
    if (!quote && ch === "]") depth--
    if (ch === " " && depth === 0 && !quote) {
      if (cur) out.push(cur)
      cur = ""
    } else cur += ch
  }
  if (cur) out.push(cur)
  return out
}

function matchesCompound(el: MiniElement, c: Compound): boolean {
  if (c.tag !== null && el.localName !== c.tag) return false
  if (c.id !== null && el.id !== c.id) return false
  if (!c.classes.every((cls) => el.classList.contains(cls))) return false
  if (!c.attrs.every((a) => el.hasAttribute(a.name) && (a.value === null || el.getAttribute(a.name) === a.value))) return false
  if (c.checked && !el.checked) return false
  return true
}

function matches(el: MiniElement, selector: string): boolean {
  return selector.split(",").some((group) => {
    const chain = parts(group).map(parseCompound)
    const last = chain.pop()
    if (!last || !matchesCompound(el, last)) return false
    let at = el.parent
    for (let i = chain.length - 1; i >= 0; i--) {
      while (at && !matchesCompound(at, chain[i]!)) at = at.parent
      if (!at) return false
      at = at.parent
    }
    return true
  })
}

// Parses the page the server rendered into elements.
export function parseHtml(markup: string): MiniElement {
  const doc = new MiniElement("#document")
  const stack: MiniElement[] = [doc]
  const token = /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[^\s=>\/]+(?:="[^"]*")?)*)\s*(\/?)>|([^<]+)/gi
  let m: RegExpExecArray | null
  while ((m = token.exec(markup)) !== null) {
    const top = stack[stack.length - 1]!
    if (m[1]) {
      const name = m[1].toLowerCase()
      const at = stack.map((e) => e.localName).lastIndexOf(name)
      if (at > 0) stack.length = at
    } else if (m[2]) {
      const el = new MiniElement(m[2].toLowerCase())
      for (const a of (m[3] ?? "").matchAll(/([^\s=>\/]+)(?:="([^"]*)")?/g)) el.setAttribute(a[1]!, decode(a[2] ?? ""))
      top.append(el)
      if (!m[4] && !VOID.has(el.localName)) stack.push(el)
    } else if (m[5] !== undefined && m[0][0] !== "<") top.append(new MiniText(decode(m[5])))
  }
  return doc
}

export type MiniBrowser = {
  document: MiniElement
  assigned: string[]
  reloaded: number
  calls: { path: string; body: unknown }[]
  respond: (path: string, body: unknown) => { status: number; body: unknown } | Promise<never>
  restore: () => void
}

// Installs a page as the global document, with a fetch that records every
// call and answers from `respond` (a string body is a page, served as HTML),
// a DOMParser over parseHtml, and a location that records navigation.
export function installPage(markup: string, respond: MiniBrowser["respond"], href = "https://vault.test/"): MiniBrowser {
  const document = parseHtml(markup)
  const g = globalThis as unknown as Record<string, unknown>
  const saved = new Map(["document", "location", "history", "fetch", "CSS", "sessionStorage", "DOMParser"].map((k) => [k, g[k]]))
  const browser: MiniBrowser = { document, assigned: [], reloaded: 0, calls: [], respond, restore: () => { for (const [k, v] of saved) g[k] = v } }
  const url = new URL(href)
  Object.assign(document, {
    createElement: (tag: string) => new MiniElement(tag),
    createTextNode: (text: string) => new MiniText(text),
    getElementById: (id: string) => document.querySelector(`#${id}`),
    importNode: (node: MiniNode) => node,
    body: document.querySelector("body"),
    readyState: "complete",
  })
  g.document = document
  g.CSS = { escape: (v: string) => v.replace(/["\\]/g, "\\$&") }
  g.DOMParser = class {
    parseFromString(markup: string): MiniElement {
      const parsed = parseHtml(markup)
      return Object.assign(parsed, { getElementById: (id: string) => parsed.querySelector(`#${id}`) })
    }
  }
  g.sessionStorage = { setItem: () => undefined, getItem: () => null, removeItem: () => undefined }
  const location = { origin: url.origin, host: url.host, pathname: url.pathname, search: url.search, hash: url.hash, href: url.href, assign: (to: string) => void browser.assigned.push(to), reload: () => void browser.reloaded++ }
  g.location = location
  g.history = { replaceState: () => void (location.hash = "") }
  g.fetch = async (path: string, init?: { body?: string }) => {
    const body = init?.body === undefined ? undefined : (JSON.parse(init.body) as unknown)
    browser.calls.push({ path: String(path), body })
    const answer = await respond(String(path), body)
    if (typeof answer.body === "string") return new Response(answer.body, { status: answer.status, headers: { "content-type": "text/html; charset=utf-8" } })
    return new Response(JSON.stringify(answer.body), { status: answer.status, headers: { "content-type": "application/json" } })
  }
  return browser
}

// Lets queued promise callbacks run.
export async function settle(times = 20): Promise<void> {
  for (let i = 0; i < times; i++) await new Promise((r) => setTimeout(r, 0))
}

export function submit(form: MiniElement): void {
  form.dispatchEvent(new MiniEvent("submit", { bubbles: true }))
}
