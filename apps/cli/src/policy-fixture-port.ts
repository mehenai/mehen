import type { ApiError, NextStep } from "@mehen/protocol/api"
import type { PolicyContext, PolicyProposalStatus, PolicyStopped } from "@mehen/protocol/policy-mode"

type FixtureApi = {
  request<T>(method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: unknown, options?: { signal?: AbortSignal }): Promise<T>
  relay(request: unknown, options?: { signal?: AbortSignal }): Promise<Response>
}

type FixtureSession = {
  api: FixtureApi
  // `workspaceSlug` is the context's canonical slug: the only slug under which
  // a workspace ask link (/w/<slug>/...) is trusted.
  config: { vault: string; tenant: string; device: string; backend: "software"; workspaceSlug?: string }
  vaultUrl: string
  configDir: string
}

type FixtureProposal = PolicyProposalStatus & {
  url: string | null
  ask: { kind: string; url: string; requestedBy: { device: string; session: string | null } } | null
  next: NextStep | null
  warning: string | null
}

export type PolicyFixturePort = {
  proposePolicy(session: FixtureSession, value: unknown, env: Record<string, string | undefined>): Promise<FixtureProposal>
  showPolicy(session: FixtureSession, item: string): Promise<PolicyContext>
  stopPolicy(session: FixtureSession, id: string): Promise<PolicyStopped>
  waitJson(api: FixtureApi, id: string): Promise<Record<string, unknown>>
  failureJson(error: unknown, vaultUrl: string | { vaultUrl: string; workspaceSlug?: string | null }): { value: Record<string, unknown>; exit: number }
  apiError: new (status: number, body: ApiError) => Error
}
