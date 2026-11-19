// The view side of MCP Apps (SEP-1865, protocol 2026-01-26): JSON-RPC 2.0
// over postMessage with the host window. Browser code: no Node APIs, and
// only messages from window.parent are read.

export const APPS_PROTOCOL_VERSION = "2026-01-26"

export type CallToolResult = { content?: unknown[]; structuredContent?: Record<string, unknown>; isError?: boolean }

export type HostCapabilities = {
  openLinks?: object
  serverTools?: object
  updateModelContext?: object
}

export type HostContext = {
  theme?: "light" | "dark"
  styles?: { variables?: Record<string, string | undefined> }
  displayMode?: string
  locale?: string
}

type Message = { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown; result?: unknown; error?: unknown }

type Listeners = {
  toolInput: ((args: Record<string, unknown>) => void)[]
  toolResult: ((result: CallToolResult) => void)[]
  toolCancelled: ((reason: string | null) => void)[]
  hostContext: ((context: HostContext) => void)[]
  teardown: (() => void)[]
}

export class BridgeError extends Error {}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

export class Bridge {
  private nextId = 1
  private readonly pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>()
  private readonly listeners: Listeners = { toolInput: [], toolResult: [], toolCancelled: [], hostContext: [], teardown: [] }
  private resize: ResizeObserver | null = null
  private lastSize = ""
  capabilities: HostCapabilities = {}
  context: HostContext = {}
  closed = false

  constructor(private readonly app: { name: string; version: string }) {
    window.addEventListener("message", (event) => {
      if (event.source !== window.parent) return
      this.receive(record(event.data) as Message)
    })
  }

  onToolInput(listener: (args: Record<string, unknown>) => void): void {
    this.listeners.toolInput.push(listener)
  }

  onToolResult(listener: (result: CallToolResult) => void): void {
    this.listeners.toolResult.push(listener)
  }

  onToolCancelled(listener: (reason: string | null) => void): void {
    this.listeners.toolCancelled.push(listener)
  }

  // Called with the merged context after initialize and after every change.
  onHostContext(listener: (context: HostContext) => void): void {
    this.listeners.hostContext.push(listener)
  }

  onTeardown(listener: () => void): void {
    this.listeners.teardown.push(listener)
  }

  // Listeners first, then ui/initialize, then the initialized notification.
  async connect(): Promise<void> {
    const result = record(await this.request("ui/initialize", { appInfo: this.app, appCapabilities: {}, protocolVersion: APPS_PROTOCOL_VERSION }))
    this.capabilities = record(result.hostCapabilities) as HostCapabilities
    this.setContext(record(result.hostContext) as HostContext)
    this.notify("ui/notifications/initialized", {})
  }

  callTool(name: string, args: Record<string, unknown>, timeoutMs?: number): Promise<CallToolResult> {
    return this.request("tools/call", { name, arguments: args }, timeoutMs) as Promise<CallToolResult>
  }

  // True when the host says it opened the link.
  async openLink(url: string): Promise<boolean> {
    const result = record(await this.request("ui/open-link", { url }))
    return result.isError !== true
  }

  async updateModelContext(params: { structuredContent: Record<string, unknown> }): Promise<void> {
    await this.request("ui/update-model-context", params)
  }

  // Reports the document's size now and whenever it changes. Called once
  // the card has drawn: a host may collapse a frame that reports 0, and a
  // collapsed frame is not laid out again until it is shown.
  watchSize(): void {
    if (this.resize !== null) return
    const root = document.documentElement
    const send = () => {
      const box = root.getBoundingClientRect()
      const size = { width: Math.ceil(box.width), height: Math.ceil(box.height) }
      const key = `${size.width}x${size.height}`
      if (key === this.lastSize || this.closed) return
      this.lastSize = key
      this.notify("ui/notifications/size-changed", size)
    }
    this.resize = new ResizeObserver(send)
    this.resize.observe(root)
    send()
  }

  private setContext(change: HostContext): void {
    const styles = change.styles ? { ...this.context.styles, ...change.styles, variables: { ...this.context.styles?.variables, ...change.styles.variables } } : this.context.styles
    this.context = { ...this.context, ...change, ...(styles ? { styles } : {}) }
    for (const listener of this.listeners.hostContext) listener(this.context)
  }

  private request(method: string, params: Record<string, unknown>, timeoutMs?: number): Promise<unknown> {
    if (this.closed) return Promise.reject(new BridgeError("the card was torn down"))
    const id = this.nextId++
    return new Promise((resolve, reject) => {
      const timer = timeoutMs === undefined ? null : setTimeout(() => settle(() => reject(new BridgeError(`${method} timed out`))), timeoutMs)
      const settle = (done: () => void) => {
        if (timer !== null) clearTimeout(timer)
        this.pending.delete(id)
        done()
      }
      this.pending.set(id, { resolve: (value) => settle(() => resolve(value)), reject: (error) => settle(() => reject(error)) })
      this.post({ jsonrpc: "2.0", id, method, params })
    })
  }

  private notify(method: string, params: Record<string, unknown>): void {
    this.post({ jsonrpc: "2.0", method, params })
  }

  private post(message: Record<string, unknown>): void {
    // A sandboxed srcdoc frame has no origin of its own to name the host by.
    window.parent.postMessage(message, "*")
  }

  private receive(message: Message): void {
    if (message.jsonrpc !== "2.0") return
    const hasId = typeof message.id === "number" || typeof message.id === "string"
    if (hasId && message.method === undefined) {
      const waiting = typeof message.id === "number" ? this.pending.get(message.id) : undefined
      if (!waiting) return
      if (message.error !== undefined) waiting.reject(new BridgeError(String(record(message.error).message ?? "the host refused the request")))
      else waiting.resolve(message.result)
      return
    }
    if (typeof message.method !== "string") return
    const params = record(message.params)
    if (hasId) {
      if (message.method === "ui/resource-teardown") {
        this.teardown()
        this.post({ jsonrpc: "2.0", id: message.id, result: {} })
      } else if (message.method === "ping") {
        this.post({ jsonrpc: "2.0", id: message.id, result: {} })
      } else {
        this.post({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: `Method ${message.method} is not supported.` } })
      }
      return
    }
    if (message.method === "ui/notifications/tool-input") for (const listener of this.listeners.toolInput) listener(record(params.arguments))
    else if (message.method === "ui/notifications/tool-result") for (const listener of this.listeners.toolResult) listener(params as CallToolResult)
    else if (message.method === "ui/notifications/tool-cancelled") for (const listener of this.listeners.toolCancelled) listener(typeof params.reason === "string" ? params.reason : null)
    else if (message.method === "ui/notifications/host-context-changed") this.setContext(params as HostContext)
  }

  private teardown(): void {
    if (this.closed) return
    this.closed = true
    this.resize?.disconnect()
    for (const listener of this.listeners.teardown) listener()
    for (const waiting of this.pending.values()) waiting.reject(new BridgeError("the card was torn down"))
  }
}
