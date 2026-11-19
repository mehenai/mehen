import { jwkThumbprint, type DeviceJwk } from "@mehen/protocol/proof"
import type { WorkloadScope, WorkloadView } from "@mehen/protocol/workload"
import type { WorkspaceDeviceScope } from "@mehen/protocol/workspace"
import { DEVICE, TENANT } from "./fake-vault.ts"

export const WORKSPACE = { id: TENANT, slug: "acme", name: "Acme" }
export const OWNER = { kind: "member", member: "mem_alex0001", name: "Alex" } as const
export const SCOPE: WorkspaceDeviceScope = { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"], privateCredentials: false }

export function meAnswer(extra: Record<string, unknown> = {}) {
  return {
    tenant: TENANT,
    device: DEVICE,
    name: "globex-broker",
    scope: SCOPE,
    frozen: false,
    fingerprint: "K7Q2 MX4D 9RTV 3HNB",
    capabilities: { environmentV2: true, runBaseUrl: true, runFiles: true, sealedEnvImport: true, policyV1: true },
    workspace: WORKSPACE,
    owner: OWNER,
    displayRev: 1,
    ...extra,
  }
}

export async function workloadView(id: string, jwk: DeviceJwk, scope: WorkloadScope, overrides: Partial<WorkloadView> = {}): Promise<WorkloadView> {
  return {
    workload: id,
    device: DEVICE,
    label: "task:42",
    thumbprint: await jwkThumbprint(jwk),
    scope,
    state: "active",
    createdAt: "2026-10-29T10:00:00.000Z",
    expiresAt: "2026-10-29T11:00:00.000Z",
    hardExpiresAt: "2026-11-05T10:00:00.000Z",
    lastSeenAt: null,
    revokedAt: null,
    revokedBy: null,
    ...overrides,
  }
}

export const PROJECT = "prj_project0001"
export const RUN = "run_run0001"

// A run's answer with one variable of every delivery the protocol has.
export function runCreated(extra: Record<string, unknown> = {}) {
  return {
    run: RUN,
    expiresAt: "2026-10-29T10:15:00.000Z",
    project: { id: PROJECT, slug: "acme-app" },
    env: "dev",
    vars: [
      { name: "DATABASE_HOST", delivery: "plain", value: "db.internal" },
      { name: "OPENAI_API_KEY", delivery: "placeholder", value: "sk-proj-mehen-placeholder-0001", item: "openai", hosts: ["api.openai.com"] },
      { name: "OPENAI_BASE_URL", delivery: "base-url", value: "http://127.0.0.1:7777/openai", item: "openai" },
      { name: "PGPASSWORD", delivery: "lease", value: "lease-value", item: "postgres" },
      { name: "SENTRY_DSN", delivery: "missing", next: { say: "Set SENTRY_DSN for this environment.", command: "mehen env set SENTRY_DSN --env dev" } },
    ],
    interceptHosts: ["api.openai.com"],
    fencedHosts: ["api.prod.example"],
    overrides: [],
    authorisation: null,
    ...extra,
  }
}

export function projectAnswer(extra: Record<string, unknown> = {}) {
  return {
    id: PROJECT,
    slug: "acme-app",
    remotes: ["github.com/acme/app"],
    defaultEnv: "dev",
    access: { level: "use", runProtected: false, editProtected: false },
    environments: [
      { name: "dev", protected: false, fences: [], fourEyes: false },
      { name: "prod", protected: true, fences: ["api.prod.example"], fourEyes: true },
    ],
    vars: [
      { name: "DATABASE_HOST", env: "dev", source: "plain", item: null, field: null },
      { name: "OPENAI_API_KEY", env: "dev", source: "item", item: "openai", field: "key" },
      { name: "STRIPE_KEY", env: "dev", source: "item", item: null, field: null, note: "This variable points at a credential outside your reach." },
    ],
    ...extra,
  }
}
