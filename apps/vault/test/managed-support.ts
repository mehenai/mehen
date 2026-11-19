// A managed workspace end to end in workerd: the platform's calls go to the
// workspace object as the Worker would hand them over after verifying the
// platform proof (P1's routes), the platform directory is a stub, and the
// devices and workloads it provisions call the real Worker with real proofs.
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { DEFAULT_PLATFORM_LIMITS, INITIAL_PLATFORM_DEFAULTS, createProof, importSealPublicKey, seal, webCryptoSigner, type PlatformDefaults, type PlatformLimits, type PlatformStatus, type WorkloadView } from "@mehen/protocol"
import { expect } from "vitest"
import { fetchWorker, freshTenant, ORIGIN } from "./helpers.ts"
import { newDeviceKey, publicJwk } from "./devices.ts"
import type { InvocationResult, PlatformInvocationAuth, SystemAuth } from "../src/vault/core.ts"
import { registerManagedDirectory, type ManagedPlatformRow, type ManagedWorkspaceStatus } from "../src/vault/managed-platform.ts"
import { AREAS } from "../src/vault/registry.ts"
import { principalOf, setSetting, setting } from "../src/vault/areas/workspace-runtime.ts"
import { VaultError } from "../src/http.ts"
import type { TenantVault } from "../src/vault/tenant-vault.ts"

export const PLATFORM = "plt_globexTest01"
export const KEY = "pky_globexKey001"
export const SUBJECT = "globex_subject_0001"

export type Directory = {
  platform: { id: string; slug: string; name: string; status: PlatformStatus }
  limits: PlatformLimits
  defaults: PlatformDefaults
  defaultsRevision: number
  workspaces: Map<string, { subject: string; status: ManagedWorkspaceStatus }>
  reads: number
  purged: { tenant: string; head: string | null }[]
}

// The platform directory as P1 keeps it, in memory, behind the signature of
// its readManagedPlatform(db, tenant): what each read answers, and what each
// purge the workspace's own alarm made recorded.
export function stubDirectory(limits: Partial<PlatformLimits> = {}): { directory: Directory; restore: () => void } {
  const directory: Directory = {
    platform: { id: PLATFORM, slug: "globex", name: "Globex", status: "active" },
    limits: { ...DEFAULT_PLATFORM_LIMITS, ...limits },
    defaults: structuredClone(INITIAL_PLATFORM_DEFAULTS),
    defaultsRevision: 1,
    workspaces: new Map(),
    reads: 0,
    purged: [],
  }
  const restore = registerManagedDirectory({
    async read(_db, tenant): Promise<ManagedPlatformRow | null> {
      directory.reads++
      const workspace = directory.workspaces.get(tenant)
      return workspace ? structuredClone({ platform: { ...directory.platform, removing: false, limits: directory.limits, defaults: directory.defaults, defaultsRevision: directory.defaultsRevision }, workspace }) : null
    },
    async purged(_db, tenant, head) { directory.purged.push({ tenant, head }) },
  })
  return { directory, restore }
}

let proofCounter = 0
export function platformAuth(subject = SUBJECT, platform = PLATFORM, overrides: Partial<PlatformInvocationAuth> = {}): PlatformInvocationAuth {
  return { kind: "platform", platform, key: KEY, subject, jti: `jti_${Date.now()}_${++proofCounter}`, iat: Math.floor(Date.now() / 1000), ...overrides }
}

export async function invokeAs(tenant: string, op: string, input: unknown, auth: PlatformInvocationAuth | SystemAuth): Promise<InvocationResult> {
  return (await env.TENANT_VAULT.getByName(tenant).invoke({ op, input, auth })) as InvocationResult
}

// The platform's call, as the Worker makes it (platform/workspace-calls.ts):
// params, query and body, null where the route has none; its answer.
export async function platform<T>(tenant: string, op: string, input: { params?: Record<string, string>; query?: unknown; body?: unknown } = {}, auth = platformAuth()): Promise<T> {
  const result = await invokeAs(tenant, op, { params: input.params ?? {}, query: input.query ?? null, body: input.body ?? null }, auth)
  expect(result.ok ? null : result.error.vaultError, op).toBeNull()
  if (!result.ok) throw new Error("unreachable")
  return result.value as T
}

// The refusal's wire error for a call expected to fail.
export async function refused(result: Promise<InvocationResult>): Promise<{ error: string; message: string } & Record<string, unknown>> {
  const settled = await result
  expect(settled.ok).toBe(false)
  if (settled.ok) throw new Error("unreachable")
  return settled.error.vaultError as { error: string; message: string } & Record<string, unknown>
}

// A platform call that passed admission (admitPlatformCall) while its subject
// was active, and reaches its handler after the subject's deletion began:
// the subject is marked deleting, as deleteSubject's first transaction marks
// it, and the handler runs as the object runs it. Answers its refusal.
export async function afterDeletionBegan(tenant: string, op: string, input: { params?: Record<string, string>; body?: unknown }, auth = platformAuth()): Promise<{ error: string; message: string } | null> {
  return runInDurableObject(env.TENANT_VAULT.getByName(tenant), async (instance: TenantVault) => {
    const ctx = instance.context
    const spec = AREAS.map((area) => area.workspaceOps?.[op]).find((found) => found !== undefined)
    if (!spec) throw new Error(`${op} is not registered`)
    const principal = principalOf(ctx, auth)
    setSetting(ctx, "managed_status", "deleting")
    try {
      await spec.handler(ctx, principal, { params: input.params ?? {}, query: null, body: input.body ?? null }, { auth, workspace: setting(ctx, "workspace", { id: tenant, slug: "managed", name: "Managed" }) })
      return null
    } catch (error) {
      if (error instanceof VaultError) return { error: error.code, message: error.message }
      throw error
    } finally {
      setSetting(ctx, "managed_status", "active")
    }
  })
}

export type Signer = { device: string; keys: CryptoKeyPair; workload?: string }

// A request through the real Worker, signed by a device's key or a workload's.
export async function signed(tenant: string, signer: Signer, path: string, input?: unknown, method = input === undefined ? "GET" : "POST"): Promise<Response> {
  const encoded = input === undefined ? null : JSON.stringify(input), url = `${ORIGIN}${path}`
  const proof = await createProof(webCryptoSigner(signer.device, signer.keys.privateKey, signer.workload), { method, url, body: encoded }, { tenant })
  return fetchWorker(path, { method, headers: { "content-type": "application/json", "Mehen-Proof": proof }, ...(encoded === null ? {} : { body: encoded }) })
}

export async function json<T>(response: Response, status = 200): Promise<T> {
  const text = await response.text()
  expect({ status: response.status, text: response.status === status ? null : text }).toEqual({ status, text: null })
  return JSON.parse(text) as T
}

export function sql<T extends Record<string, SqlStorageValue>>(tenant: string, query: string, ...bindings: SqlStorageValue[]): Promise<T[]> {
  return runInDurableObject(env.TENANT_VAULT.getByName(tenant), (_instance: TenantVault, state) => state.storage.sql.exec<T>(query, ...bindings).toArray())
}

// A subject with its workspace, a device for one agent, and a workload of it.
export async function managedSubject(limits: Partial<PlatformLimits> = {}) {
  const { directory, restore } = stubDirectory(limits)
  const tenant = freshTenant()
  directory.workspaces.set(tenant, { subject: SUBJECT, status: "creating" })
  await platform(tenant, "platform.subjects.ensure", { body: {} })
  directory.workspaces.set(tenant, { subject: SUBJECT, status: "active" })
  async function device(modes: ("relay" | "placeholder")[] = ["relay", "placeholder"], name = "agent-1") {
    const keys = await newDeviceKey()
    const view = await platform<{ device: string }>(tenant, "platform.devices.create", { body: { name, jwk: await publicJwk(keys), modes, label: "globex:agent-1" } })
    return { device: view.device, keys }
  }
  async function workload(owner: Signer, scope: Record<string, unknown> = {}, label = "globex:grant-1"): Promise<Signer & { view: WorkloadView }> {
    const keys = await newDeviceKey()
    const view = await json<WorkloadView>(await signed(tenant, owner, "/v1/workloads", { jwk: await publicJwk(keys), label, scope }), 201)
    return { device: owner.device, keys, workload: view.workload, view }
  }
  // An item through a sealed intake, as the person's browser would seal it.
  async function intake(slug: string, service: Record<string, unknown>, values: Record<string, string>, publicFields: Record<string, string> = {}) {
    const opened = await platform<{ intake: string; sealKey: { jwk: JsonWebKey } }>(tenant, "platform.intakes.create", { body: { slug, service } })
    const key = await importSealPublicKey(opened.sealKey.jwk)
    const sealed = Object.fromEntries(await Promise.all(Object.entries(values).map(async ([field, value]) => [field, await seal(key, value, `intake/${opened.intake}/${field}`)] as const)))
    return platform<{ item: { slug: string; hosts: string[] } }>(tenant, "platform.intakes.submit", { params: { intake: opened.intake }, body: { sealed, publicFields } })
  }
  return { directory, restore, tenant, device, workload, intake }
}
