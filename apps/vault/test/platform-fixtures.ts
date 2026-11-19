// Platform mode in tests: a fresh directory, platforms registered straight
// into D1 with real P-256 keys, requests signed with the protocol's own
// platform proof, and a stand-in for the managed workspaces' operations
// that records every call (the workspaces' own behaviour is tested with
// them).

import { createExecutionContext } from "cloudflare:test"
import { DEFAULT_PLATFORM_LIMITS, INITIAL_PLATFORM_DEFAULTS, PLATFORM_PROOF_HEADER, type PlatformLimits, type PlatformSigner, canonicalJson, createPlatformProof, jwkThumbprint, randomId, webCryptoPlatformSigner } from "@mehen/protocol"
import type { Env } from "../src/env.ts"
import { WORKSPACE_GENERATION } from "../src/directory/workspace-cutover.ts"
import type { InvocationResult } from "../src/vault/core.ts"
import { ORIGIN } from "./helpers.ts"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"

export type TestPlatform = { id: string; slug: string; key: string; signer: PlatformSigner }

export type WorkspaceCall = { tenant: string; op: string; input: unknown; auth: Record<string, unknown> }
export type WorkspaceAnswer = (call: WorkspaceCall) => InvocationResult | Promise<InvocationResult>

export const PURGE_AFTER = Date.UTC(2026, 11, 1)

// What a managed workspace answers in these tests, unless a test says otherwise.
export const DEFAULT_WORKSPACE_ANSWER: WorkspaceAnswer = (call) => {
  switch (call.op) {
    case "platform.subjects.ensure":
    case "platform.subjects.get":
      return { ok: true, value: { counts: { devices: 1, items: 2, projects: 3 } } }
    case "platform.subjects.remove":
      return { ok: true, value: { purgeAfter: PURGE_AFTER } }
    case "platform.subjects.purge":
      return { ok: true, value: { auditHead: `head-${call.tenant}` } }
    default:
      return { ok: false, error: { vaultError: { error: "not_found", message: "No such operation." }, status: 404 } }
  }
}

export function fakeWorkspaces(answer: WorkspaceAnswer = DEFAULT_WORKSPACE_ANSWER): { namespace: Env["TENANT_VAULT"]; calls: WorkspaceCall[] } {
  const calls: WorkspaceCall[] = []
  const namespace = {
    getByName(tenant: string) {
      return {
        async cutoverGeneration() {
          return WORKSPACE_GENERATION
        },
        async invoke(invocation: { op: string; input: unknown; auth: Record<string, unknown> }) {
          const call = { tenant, op: invocation.op, input: structuredClone(invocation.input), auth: { ...invocation.auth } }
          calls.push(call)
          return answer(call)
        },
      }
    },
  }
  return { namespace: namespace as unknown as Env["TENANT_VAULT"], calls }
}

export type PlatformTestEnv = { env: Env; calls: WorkspaceCall[] }

export async function platformEnv(answer?: WorkspaceAnswer): Promise<PlatformTestEnv> {
  const f = await createWorkspaceFixture()
  const workspaces = fakeWorkspaces(answer)
  return { env: { ...f.env, TENANT_VAULT: workspaces.namespace }, calls: workspaces.calls }
}

export async function newPlatformKey(): Promise<{ privateKey: CryptoKey; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string } }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const exported = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey
  return { privateKey: pair.privateKey, jwk: { kty: "EC", crv: "P-256", x: exported.x as string, y: exported.y as string } }
}

export async function addPlatformKey(env: Env, platform: string, options: { expiresAt?: number; revokedAt?: number } = {}): Promise<{ key: string; signer: PlatformSigner }> {
  const { privateKey, jwk } = await newPlatformKey()
  const key = randomId("pky")
  await env.DB.prepare("INSERT INTO platform_keys (id,platform,jwk,thumbprint,created_at,created_by,expires_at,revoked_at) VALUES (?,?,?,?,?,?,?,?)")
    .bind(key, platform, canonicalJson(jwk), await jwkThumbprint(jwk), Date.now(), "operator:test", options.expiresAt ?? null, options.revokedAt ?? null)
    .run()
  return { key, signer: webCryptoPlatformSigner(platform, key, privateKey) }
}

export async function registerPlatform(env: Env, options: { slug?: string; status?: "active" | "suspended" | "retiring" | "retired"; retireAfter?: number; limits?: Partial<PlatformLimits> } = {}): Promise<TestPlatform> {
  const id = randomId("plt")
  const slug = options.slug ?? `p${crypto.randomUUID().replaceAll("-", "").slice(0, 12)}`
  const now = Date.now()
  await env.DB.prepare("INSERT INTO platforms (id,slug,name,status,limits,defaults,defaults_rev,created_at,created_by,status_at,status_by,retire_after) VALUES (?,?,?,?,?,?,1,?,'operator:test',?,'operator:test',?)")
    .bind(id, slug, `Platform ${slug}`, options.status ?? "active", canonicalJson({ ...DEFAULT_PLATFORM_LIMITS, ...options.limits }), canonicalJson(INITIAL_PLATFORM_DEFAULTS), now, now, options.status === "retiring" ? (options.retireAfter ?? now + 86_400_000) : null)
    .run()
  const { key, signer } = await addPlatformKey(env, id)
  return { id, slug, key, signer }
}

export type SignedRequest = { method: string; path: string; body?: unknown; now?: number; headers?: Record<string, string>; signer?: PlatformSigner; proof?: string | null; sendBody?: string }

export async function signedRequest(platform: TestPlatform, request: SignedRequest): Promise<Request> {
  const url = `${ORIGIN}${request.path}`
  const body = request.body === undefined ? null : JSON.stringify(request.body)
  const proof = request.proof === undefined ? await createPlatformProof(request.signer ?? platform.signer, { method: request.method, url, body }, request.now === undefined ? {} : { now: request.now }) : request.proof
  const headers: Record<string, string> = { ...(body !== null ? { "content-type": "application/json" } : {}), ...(proof !== null ? { [PLATFORM_PROOF_HEADER]: proof } : {}), ...request.headers }
  const sent = request.sendBody ?? body
  return new Request(url, { method: request.method, headers, ...(sent !== null ? { body: sent } : {}) })
}

export async function platformFetch(env: Env, platform: TestPlatform, request: SignedRequest): Promise<Response> {
  return fetchPlatformRequest(env, await signedRequest(platform, request))
}

export async function fetchPlatformRequest(env: Env, request: Request): Promise<Response> {
  const worker = (await import("../src/index.ts")).default
  return worker.fetch(request as Request<unknown, IncomingRequestCfProperties>, env, createExecutionContext())
}

export async function answerOf(response: Response): Promise<{ status: number; body: Record<string, unknown> }> {
  return { status: response.status, body: (await response.json()) as Record<string, unknown> }
}

export async function addSubject(env: Env, platform: string, subject: string, status: "creating" | "active" | "deleting" | "deleted" | "purged" = "active", options: { createdAt?: number; purgeAfter?: number } = {}): Promise<string> {
  const tenant = `tn_${crypto.randomUUID().replaceAll("-", "").slice(0, 20)}`
  await env.DB.prepare("INSERT INTO managed_workspaces (tenant,platform,subject,subject_hash,status,created_at,deleted_at,purge_after) VALUES (?,?,?,?,?,?,?,?)")
    .bind(tenant, platform, status === "purged" ? null : subject, `hash-${subject}`, status, options.createdAt ?? Date.now(), status === "deleted" || status === "purged" ? Date.now() : null, options.purgeAfter ?? (status === "deleted" ? PURGE_AFTER : null))
    .run()
  return tenant
}
