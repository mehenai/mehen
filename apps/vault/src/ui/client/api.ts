// Same-origin JSON calls to the vault's /api routes, and the passkey
// step-up every widening action goes through.

import type { ApiError, EnrolApproveStepUpRequest, StepUpActionInput, StepUpProof } from "@mehen/protocol/api"
import { type PublicKeyCredentialRequestOptionsJSON, startAuthentication } from "@simplewebauthn/browser"
import { type ShellState, WORKSPACE_HEADER } from "./shell-logic.ts"

export class VaultFailure extends Error {
  readonly status: number
  readonly body: ApiError
  constructor(status: number, body: ApiError) {
    super(body.message)
    this.status = status
    this.body = body
  }
}

function isApiError(value: unknown): value is ApiError {
  return typeof value === "object" && value !== null && typeof (value as ApiError).error === "string" && typeof (value as ApiError).message === "string"
}

// Status of a call this tab refused itself, before or after the network.
export const STALE_TAB_STATUS = 409

// Set on a workspace page: a stale tab refuses every call but sign-out,
// before anything is sent.
let callGuard: ((path: string) => ApiError | null) | null = null

export function setCallGuard(guard: ((path: string) => ApiError | null) | null): void {
  callGuard = guard
}

// GET without a body, POST with one.
export async function api<T>(path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
  const refused = callGuard?.(path) ?? null
  if (refused !== null) throw new VaultFailure(STALE_TAB_STATUS, refused)
  let response: Response
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: body === undefined ? { accept: "application/json", ...extraHeaders } : { accept: "application/json", "content-type": "application/json", ...extraHeaders },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  } catch {
    throw new VaultFailure(0, { error: "upstream_failed", message: "Could not reach the vault.", next: { say: "Check your connection and try again." } })
  }
  let parsed: unknown = null
  try {
    parsed = await response.json()
  } catch {
    parsed = null
  }
  if (!response.ok) {
    throw new VaultFailure(
      response.status,
      isApiError(parsed) ? parsed : { error: "internal", message: `The vault answered with an error (${response.status}).`, next: { say: "Reload the page and try again." } },
    )
  }
  return parsed as T
}

// A call under the workspace prefix, /api/w/<slug><path>, naming the
// workspace id in its header. Refused with nothing sent once the tab is
// stale; a reply that lands after the tab moved on is dropped.
export async function workspaceApi<T>(shell: ShellState, path: string, body?: unknown): Promise<T> {
  const start = shell.begin()
  if (!start.ok) throw new VaultFailure(STALE_TAB_STATUS, start.refusal)
  const value = await api<T>(shell.apiPath(path), body, { [WORKSPACE_HEADER]: shell.identity.workspace.id })
  const late = shell.settle(start.generation)
  if (late !== null) throw new VaultFailure(STALE_TAB_STATUS, late)
  return value
}

// A workspace read kept for this page view, keyed by the tab's full
// identity; never kept if the tab moved on while it was in flight.
export async function workspaceRead<T>(shell: ShellState, path: string): Promise<T> {
  const kept = shell.cached<T>(path)
  if (kept !== undefined) return kept
  const start = shell.begin()
  if (!start.ok) throw new VaultFailure(STALE_TAB_STATUS, start.refusal)
  const value = await workspaceApi<T>(shell, path)
  shell.remember(path, start.generation, value)
  return value
}

// POST /api/stepup { action } -> { nonce, options }; the passkey signs a
// challenge that commits to the nonce and this exact action.
export async function stepUp(action: StepUpActionInput | EnrolApproveStepUpRequest): Promise<StepUpProof> {
  const { nonce, options } = await api<{ nonce: string; options: PublicKeyCredentialRequestOptionsJSON }>("/api/stepup", { action })
  const assertion = await startAuthentication({ optionsJSON: options })
  return { nonce, assertion }
}

// A workspace POST that answers a file (a backup export): the bytes and
// the response's headers, with the same stale-tab guard and refusals as
// workspaceApi.
export async function workspaceFile(shell: ShellState, path: string, body: unknown): Promise<{ bytes: Uint8Array<ArrayBuffer>; headers: Headers }> {
  const full = shell.apiPath(path)
  const refused = callGuard?.(full) ?? null
  if (refused !== null) throw new VaultFailure(STALE_TAB_STATUS, refused)
  const start = shell.begin()
  if (!start.ok) throw new VaultFailure(STALE_TAB_STATUS, start.refusal)
  let response: Response
  try {
    response = await fetch(full, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { accept: "application/octet-stream, application/json", "content-type": "application/json", [WORKSPACE_HEADER]: shell.identity.workspace.id }, body: JSON.stringify(body) })
  } catch {
    throw new VaultFailure(0, { error: "upstream_failed", message: "Could not reach the vault.", next: { say: "Check your connection and try again." } })
  }
  if (!response.ok) {
    let parsed: unknown = null
    try { parsed = await response.json() } catch { parsed = null }
    throw new VaultFailure(response.status, isApiError(parsed) ? parsed : { error: "internal", message: `The vault answered with an error (${response.status}).`, next: { say: "Reload the page and try again." } })
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  const late = shell.settle(start.generation)
  if (late !== null) throw new VaultFailure(STALE_TAB_STATUS, late)
  return { bytes, headers: response.headers }
}
