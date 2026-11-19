// Shared test helpers: a fresh tenant per test, direct DO invocations, and
// requests through the real Worker.

import { createExecutionContext } from "cloudflare:test"
import { env, exports } from "cloudflare:workers"
import type { Invocation, InvocationResult } from "../src/vault/core.ts"

export const ORIGIN = "https://vault.test"

export function freshTenant(): string {
  const raw = crypto.getRandomValues(new Uint8Array(12))
  return `tn_${Array.from(raw, (b) => (b % 36).toString(36)).join("")}`
}

export async function invoke(tenant: string, invocation: Invocation): Promise<InvocationResult> {
  return (await env.TENANT_VAULT.getByName(tenant).invoke(invocation)) as InvocationResult
}

export function system(op: string, input?: unknown): Invocation {
  return { op, input, auth: { kind: "system", reason: "test" } }
}

export function owner(op: string, input?: unknown, stepUp?: Invocation["auth"] extends infer A ? A extends { kind: "member"; stepUp?: infer S } ? S : never : never): Invocation {
  return { op, input, auth: { kind: "member", member: "mem_test", role: "owner", ...(stepUp ? { stepUp } : {}) } }
}

export function fetchWorker(path: string, init?: RequestInit): Promise<Response> {
  return exports.default.fetch(new Request(`${ORIGIN}${path}`, init))
}

// A fabricated device principal for calling area handlers directly inside
// runInDurableObject, before or without a real enrolment.
export function testDevice(overrides: Partial<import("../src/vault/core.ts").DevicePrincipal> = {}): import("../src/vault/core.ts").DevicePrincipal {
  return {
    kind: "device",
    device: "dev_test",
    name: "test-machine",
    scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder", "lease"] },
    session: null,
    grant: null,
    workload: null,
    ...overrides,
  }
}

// Real Worker entry with an explicitly supplied isolated workspace directory.
export async function fetchWorkspaceWorker(env: import("../src/env.ts").Env, path: string, init?: RequestInit<IncomingRequestCfProperties>): Promise<Response> {
  const worker = (await import("../src/index.ts")).default
  return worker.fetch(new Request<unknown, IncomingRequestCfProperties>(`${ORIGIN}${path}`, init), env, createExecutionContext())
}
