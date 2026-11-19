// The Worker's calls into a managed workspace object. A subject route
// becomes the operation `platform.<route name>` with the input
// `{ params, query, body }` (its path parameters without the subject, each
// part already parsed by the route's schemas, null when the route has
// none). The life-cycle operations below are the same shape; the
// directory's sweeps make them with system auth.

import { z } from "zod"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import type { PlatformInvocationAuth, SystemAuth, WorkspaceVaultStub } from "../vault/core.ts"

export type PlatformOperationInput = { params: Record<string, string>; query: unknown; body: unknown }

export const PLATFORM_SYSTEM_AUTH: SystemAuth = { kind: "system", reason: "platform directory" }

// Platform auth is constructed only here and by the platform routes, after
// the platform proof verified (platform/auth.ts).
export async function callPlatformWorkspace(env: Env, tenant: string, op: string, input: PlatformOperationInput, auth: PlatformInvocationAuth | SystemAuth): Promise<unknown> {
  const workspace: WorkspaceVaultStub = env.TENANT_VAULT.getByName(tenant)
  const result = await workspace.invoke({ op, input, auth })
  if (result.ok) return result.value
  const { error, message, ...extra } = result.error.vaultError
  throw new VaultError(error, message, extra)
}

const SubjectCountsSchema = z.object({ counts: z.object({ devices: z.number().int().nonnegative(), items: z.number().int().nonnegative(), projects: z.number().int().nonnegative() }) })
export type SubjectCounts = z.infer<typeof SubjectCountsSchema>["counts"]

const NO_INPUT: PlatformOperationInput = { params: {}, query: null, body: null }

function answer<T extends z.ZodType>(schema: T, value: unknown, op: string): z.infer<T> {
  const parsed = schema.safeParse(value)
  if (parsed.success) return parsed.data
  console.error(JSON.stringify({ at: "platform.workspace.answer", op }))
  throw new VaultError("internal", "Something went wrong inside the vault.")
}

// Makes the managed workspace for its subject, or finds it made: the
// subject member, the platform's name and the audit chain's first link.
export async function ensureSubjectWorkspace(env: Env, tenant: string, auth: PlatformInvocationAuth): Promise<SubjectCounts> {
  return answer(SubjectCountsSchema, await callPlatformWorkspace(env, tenant, "platform.subjects.ensure", { params: {}, query: null, body: {} }, auth), "platform.subjects.ensure").counts
}

export async function subjectWorkspaceCounts(env: Env, tenant: string, auth: PlatformInvocationAuth): Promise<SubjectCounts> {
  return answer(SubjectCountsSchema, await callPlatformWorkspace(env, tenant, "platform.subjects.get", NO_INPUT, auth), "platform.subjects.get").counts
}

// Every device revoked, every secret and item deleted, the audit kept; the
// answer is when the workspace may be erased. Idempotent.
export async function removeSubjectWorkspace(env: Env, tenant: string, auth: PlatformInvocationAuth | SystemAuth): Promise<{ purgeAfter: number }> {
  return answer(z.object({ purgeAfter: z.number().int().nonnegative() }), await callPlatformWorkspace(env, tenant, "platform.subjects.remove", { params: {}, query: null, body: {} }, auth), "platform.subjects.remove")
}

// Erases the workspace object's storage and answers its last audit head,
// or null when it was already erased. The object records the head in D1
// before it erases anything (areas/managed.ts purgeSubject). `early` is for
// a platform being removed: the object purges before its own date only if
// the directory also says the platform is being removed.
export async function purgeSubjectWorkspace(env: Env, tenant: string, early = false): Promise<{ auditHead: string | null }> {
  const input = early ? { params: {}, query: null, body: { early: true } } : NO_INPUT
  return answer(z.object({ auditHead: z.string().nullable() }), await callPlatformWorkspace(env, tenant, "platform.subjects.purge", input, PLATFORM_SYSTEM_AUTH), "platform.subjects.purge")
}
