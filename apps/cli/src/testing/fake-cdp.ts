// A fake Chrome DevTools endpoint on Bun.serve for mehen fill's tests: it
// answers /json/version, takes one browser-level WebSocket, records every
// call and answers each method from a handler a test sets.

import type { Server, ServerWebSocket } from "bun"

export type CdpCall = { id: number; method: string; params: Record<string, unknown>; sessionId: string | null }
// A result, a protocol error, or "silent" to never answer.
export type CdpAnswer = Record<string, unknown> | { error: string } | "silent"
export type CdpHandler = (call: CdpCall, fake: FakeCdp) => CdpAnswer | Promise<CdpAnswer>

export class FakeCdp {
  readonly calls: CdpCall[] = []
  readonly handlers = new Map<string, CdpHandler>()
  readonly browserId = "fake-browser-1"
  versionAnswer: (() => Response) | null = null
  private readonly server: Server<undefined>
  private socket: ServerWebSocket<undefined> | null = null

  constructor() {
    this.server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: (request, server) => {
        const url = new URL(request.url)
        if (url.pathname === "/json/version") return this.versionAnswer ? this.versionAnswer() : Response.json({ Browser: "Chrome/142.0.0.0", webSocketDebuggerUrl: this.wsUrl })
        if (url.pathname.startsWith("/devtools/") && server.upgrade(request)) return undefined
        return new Response("not found", { status: 404 })
      },
      websocket: {
        open: (ws) => {
          this.socket = ws
        },
        message: (ws, data) => {
          void this.receive(ws, typeof data === "string" ? data : new TextDecoder().decode(data))
        },
        close: () => {
          this.socket = null
        },
      },
    })
  }

  get port(): number {
    return this.server.port as number
  }

  get wsUrl(): string {
    return `ws://127.0.0.1:${this.port}/devtools/browser/${this.browserId}`
  }

  get httpUrl(): string {
    return `http://127.0.0.1:${this.port}`
  }

  on(method: string, handler: CdpHandler): this {
    this.handlers.set(method, handler)
    return this
  }

  methods(): string[] {
    return this.calls.map((call) => call.method)
  }

  emit(method: string, params: Record<string, unknown>, sessionId: string | null = null): void {
    this.socket?.send(JSON.stringify({ method, params, ...(sessionId ? { sessionId } : {}) }))
  }

  dropConnection(): void {
    this.socket?.close()
  }

  stop(): void {
    this.server.stop(true)
  }

  private async receive(ws: ServerWebSocket<undefined>, text: string): Promise<void> {
    const message = JSON.parse(text) as { id: number; method: string; params?: Record<string, unknown>; sessionId?: string }
    const call: CdpCall = { id: message.id, method: message.method, params: message.params ?? {}, sessionId: message.sessionId ?? null }
    this.calls.push(call)
    const handler = this.handlers.get(call.method)
    const answer = handler ? await handler(call, this) : {}
    if (answer === "silent") return
    const sessionId = call.sessionId ? { sessionId: call.sessionId } : {}
    if (typeof answer.error === "string" && Object.keys(answer).length === 1) ws.send(JSON.stringify({ id: call.id, error: { code: -32000, message: answer.error }, ...sessionId }))
    else ws.send(JSON.stringify({ id: call.id, result: answer, ...sessionId }))
  }
}
