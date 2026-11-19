type JsonRpcId = string | number

// The tools/call requests in flight, by JSON-RPC id, so a host's
// notifications/cancelled can stop the one it names: its signal aborts the
// poll in flight, no further poll is signed, progress stops at once, and
// no response is sent for it.
export class CallRegistry {
  private readonly calls = new Map<JsonRpcId, AbortController>()

  begin(id: JsonRpcId): AbortSignal {
    const controller = new AbortController()
    this.calls.set(id, controller)
    return controller.signal
  }

  end(id: JsonRpcId): void {
    this.calls.delete(id)
  }

  // True when a call with that id was in flight.
  cancel(id: unknown): boolean {
    if (typeof id !== "string" && typeof id !== "number") return false
    const controller = this.calls.get(id)
    if (!controller) return false
    controller.abort()
    return true
  }
}
