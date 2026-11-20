// The seam between the CLI's commands and the vault: one implementation
// speaks HTTP with device proofs; mehen run (the local relay) and tests
// take it as a parameter.

import type { ApiError, RelayRequestInput } from "@mehen/protocol/api"

// The identity of the call that failed (origin, workspace, device), as the
// client that made it knew it: an ask synthesised from the refusal carries
// exactly this provenance, never one chosen again at rendering time.
export type CallContext = { origin: string; workspace: { id: string; slug: string; name: string } | null; device: string | null }

export class VaultApiError extends Error {
  readonly status: number
  readonly body: ApiError
  readonly context: CallContext | null

  constructor(status: number, body: ApiError, context: CallContext | null = null) {
    super(body.message)
    this.status = status
    this.body = body
    this.context = context
  }
}

// The vault could not be reached at all: DNS, refused connection, TLS, reset.
export class VaultNetworkError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "VaultNetworkError"
  }
}

// A relayed write (any method but GET, HEAD or OPTIONS) whose connection
// failed once it may have reached the vault: the vault may have sent it on
// to the upstream, so repeating it could do it twice.
export class RelayOutcomeUnknownError extends VaultNetworkError {
  constructor(message: string) {
    super(message)
    this.name = "RelayOutcomeUnknownError"
  }
}

// The vault's relay answer carried neither Mehen-Upstream nor mehen-error:
// something in front of the vault, such as a proxy, may have sent it.
export class RelayUnmarkedAnswerError extends VaultApiError {}

// Methods a repeat cannot make do more than the first did. Every other
// method, DELETE and PUT included, is treated as a write that may not be
// repeated blind: an upstream need not make them idempotent.
const RETRY_SAFE_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"])

export function retrySafeMethod(method: string): boolean {
  return RETRY_SAFE_METHODS.has(method.toUpperCase())
}

export type VaultRequestOptions = {
  // Aborting rejects with the signal's reason, not a VaultNetworkError.
  signal?: AbortSignal
  // Called with the jti of the one proof the request carries, before it is
  // sent (a fill's box is sealed under it). Never logged or printed.
  onProof?: (jti: string) => void
}

export type VaultApi = {
  // Signed JSON request to /v1/*. Throws VaultApiError for a vault refusal.
  request<T>(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown, options?: VaultRequestOptions): Promise<T>
  // Signed POST /v1/relay. Resolves with the upstream response (Mehen-Upstream: 1)
  // or throws VaultApiError for a vault refusal (Mehen-Error: 1). The signal
  // also stops the body: reading it after an abort rejects.
  relay(request: RelayRequestInput, options?: VaultRequestOptions): Promise<Response>
}
