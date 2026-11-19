// /v1/platform: every route in PLATFORM_ROUTES, signed with a platform
// proof. The Worker authenticates the call (platform/auth.ts), has the
// platform's PlatformVault spend the nonce and count its limits, parses the
// path, query and body with the route's own schemas, then answers from the
// directory or calls the subject's managed workspace. Every answer is
// re-parsed with the route's answer schema, which drops any member the
// contract does not name, so no stored row passes through as it is. No
// answer carries a secret value, a page link or a `next.url`.

import { PLATFORM_PATH_PREFIX, PLATFORM_ROUTES, PLATFORM_SUBJECTS_PAGE_SIZE, type PlatformDefaults, type PlatformRoute, type PlatformRouteName, bodyHash, canonicalJson, platformSubjectHash, sha256B64 } from "@mehen/protocol"
import { z } from "zod"
import { VaultError, errorResponse, json, readBody } from "../http.ts"
import { matchPath } from "../router.ts"
import { type PlatformCaller, authenticatePlatform } from "../platform/auth.ts"
import type { PlatformInvocationAuth } from "../vault/core.ts"
import { type ManagedWorkspaceRecord, findSubjectWorkspace, readPlatform } from "../platform/registry.ts"
import { callPlatformWorkspace, ensureSubjectWorkspace, removeSubjectWorkspace, subjectWorkspaceCounts } from "../platform/workspace-calls.ts"
import { randomId } from "../vault/core.ts"
import type { RequestContext } from "./context.ts"

type Route = (typeof PLATFORM_ROUTES)[number]

// What a route handler has once the call is authenticated, admitted and parsed.
type PlatformCall = {
  rc: RequestContext
  route: Route
  caller: PlatformCaller
  params: Record<string, string>
  query: unknown
  body: unknown
  now: number
}

type PlatformAnswer = { status: number; answer: unknown }

const SUBJECT_NOT_FOUND = "No such subject."
const LIVE = "('creating','active','deleting')"

export function isPlatformPath(pathname: string): boolean {
  return pathname === PLATFORM_PATH_PREFIX || pathname.startsWith(`${PLATFORM_PATH_PREFIX}/`)
}

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

function badRequest(part: string, error: z.ZodError): VaultError {
  const issue = error.issues[0]
  return new VaultError("bad_request", `Invalid request: ${issue ? `${[part, ...issue.path].join(".")} ${issue.message}` : part}.`)
}

function parseParams(route: PlatformRoute, raw: Record<string, string>): Record<string, string> {
  const params: Record<string, string> = {}
  for (const [name, schema] of Object.entries(route.params)) {
    const parsed = schema.safeParse(raw[name])
    if (!parsed.success) throw badRequest(name, parsed.error)
    params[name] = parsed.data
  }
  return params
}

function parseQuery(route: PlatformRoute, url: URL): unknown {
  const keys = [...url.searchParams.keys()]
  if (route.query === null) {
    if (keys.length > 0) throw new VaultError("bad_request", "This route takes no query.")
    return null
  }
  if (new Set(keys).size !== keys.length) throw new VaultError("bad_request", "Send each query parameter once.")
  const parsed = route.query.safeParse(Object.fromEntries(url.searchParams))
  if (!parsed.success) throw badRequest("query", parsed.error)
  return parsed.data
}

function parseBody(route: PlatformRoute, bytes: Uint8Array): unknown {
  if (route.body === null) {
    if (bytes.length > 0) throw new VaultError("bad_request", "This route takes no body.")
    return null
  }
  let value: unknown
  try {
    value = bytes.length === 0 ? {} : JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes))
  } catch {
    throw new VaultError("bad_request", "The body must be JSON.")
  }
  const parsed = route.body.safeParse(value)
  if (!parsed.success) throw badRequest("body", parsed.error)
  return parsed.data
}

function subjectOf(call: PlatformCall): string {
  const subject = call.params.subject
  if (subject === undefined) throw new Error("subject route without a subject")
  return subject
}

function platformAuth(call: PlatformCall): PlatformInvocationAuth {
  return { kind: "platform", platform: call.caller.platform.id, key: call.caller.key, subject: subjectOf(call), jti: call.caller.claims.jti, iat: call.caller.claims.iat }
}

function withoutSubject(params: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(params).filter(([name]) => name !== "subject"))
}

// ---------------------------------------------------------------- the platform

async function viewPlatform(call: PlatformCall): Promise<PlatformAnswer> {
  const { platform } = call.caller
  const db = call.rc.env.DB
  const [keys, usage] = await db.batch<Record<string, unknown>>([
    db.prepare("SELECT id,created_at,expires_at,revoked_at FROM platform_keys WHERE platform=? ORDER BY created_at,id").bind(platform.id),
    db.prepare(`SELECT COUNT(*) AS subjects FROM managed_workspaces WHERE platform=? AND status IN ${LIVE}`).bind(platform.id),
  ])
  const keyRows = z.array(z.object({ id: z.string(), created_at: z.number(), expires_at: z.number().nullable(), revoked_at: z.number().nullable() })).parse(keys?.results ?? [])
  const subjects = z.object({ subjects: z.number() }).parse(usage?.results?.[0]).subjects
  return {
    status: 200,
    answer: {
      platform: { id: platform.id, slug: platform.slug, name: platform.name, status: platform.status },
      limits: platform.limits,
      defaults: platform.defaults,
      defaultsRevision: platform.defaultsRevision,
      usage: { subjects },
      keys: keyRows.map((k) => ({ id: k.id, createdAt: iso(k.created_at), expiresAt: k.expires_at === null ? null : iso(k.expires_at), revoked: k.revoked_at !== null })),
    },
  }
}

async function listSubjects(call: PlatformCall): Promise<PlatformAnswer> {
  const { cursor } = z.object({ cursor: z.string().optional() }).parse(call.query)
  const rows = await call.rc.env.DB
    .prepare("SELECT tenant,subject,status,created_at FROM managed_workspaces WHERE platform=? AND status!='purged' AND tenant>? ORDER BY tenant LIMIT ?")
    .bind(call.caller.platform.id, cursor ?? "", PLATFORM_SUBJECTS_PAGE_SIZE + 1)
    .all<{ tenant: string; subject: string; status: string; created_at: number }>()
  const page = rows.results.slice(0, PLATFORM_SUBJECTS_PAGE_SIZE)
  return {
    status: 200,
    answer: {
      subjects: page.map((r) => ({ subject: r.subject, status: r.status, createdAt: iso(r.created_at) })),
      next: rows.results.length > PLATFORM_SUBJECTS_PAGE_SIZE ? (page.at(-1)?.tenant ?? null) : null,
    },
  }
}

async function digestOf(value: unknown): Promise<string> {
  return sha256B64(canonicalJson(value))
}

async function putDefaults(call: PlatformCall): Promise<PlatformAnswer> {
  const { platform, key } = call.caller
  const defaults = call.body as PlatformDefaults
  const db = call.rc.env.DB
  const current = await readPlatform(db, platform.id)
  if (!current) throw new VaultError("not_found", "No such platform.")
  const revision = current.defaultsRevision + 1
  const detail = { revision, before: await digestOf(current.defaults), after: await digestOf(defaults) }
  const [updated] = await db.batch([
    db.prepare("UPDATE platforms SET defaults=?,defaults_rev=? WHERE id=? AND defaults_rev=?").bind(canonicalJson(defaults), revision, platform.id, current.defaultsRevision),
    db.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) SELECT ?,?,?,?,'defaults.put',? WHERE changes()=1").bind(randomId("pev"), platform.id, call.now, `platform:${key}`, JSON.stringify(detail)),
  ])
  if ((updated?.meta.changes ?? 0) !== 1) throw new VaultError("conflict", "The defaults changed while this call ran; read them and try again.")
  await call.rc.env.PLATFORM_VAULT.getByName(platform.id).audit({ actor: `platform:${platform.id}`, action: "defaults.put", detail: { ...detail, by: { platform: platform.id, key }, jti: call.caller.claims.jti } }, call.now)
  return { status: 200, answer: { defaults, defaultsRevision: revision } }
}

async function removeAllSubjects(call: PlatformCall): Promise<PlatformAnswer> {
  const { platform, key } = call.caller
  const { confirm } = z.object({ confirm: z.string() }).parse(call.body)
  if (confirm !== platform.slug) throw new VaultError("bad_request", "Confirm with this platform's own slug.")
  const db = call.rc.env.DB
  const [marked, deleting] = await db.batch<Record<string, unknown>>([
    db.prepare("UPDATE managed_workspaces SET status='deleting' WHERE platform=? AND status IN ('creating','active')").bind(platform.id),
    db.prepare("SELECT COUNT(*) AS n FROM managed_workspaces WHERE platform=? AND status='deleting'").bind(platform.id),
  ])
  const count = z.object({ n: z.number() }).parse(deleting?.results?.[0]).n
  const detail = { marked: marked?.meta.changes ?? 0, deleting: count }
  await db.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) VALUES (?,?,?,?,'subjects.remove_all',?)").bind(randomId("pev"), platform.id, call.now, `platform:${key}`, JSON.stringify(detail)).run()
  await call.rc.env.PLATFORM_VAULT.getByName(platform.id).audit({ actor: `platform:${platform.id}`, action: "subjects.remove_all", detail: { ...detail, by: { platform: platform.id, key }, jti: call.caller.claims.jti } }, call.now)
  return { status: 200, answer: { deleting: count } }
}

// ---------------------------------------------------------------- a subject

function subjectView(subject: string, row: ManagedWorkspaceRecord, counts: { devices: number; items: number; projects: number }) {
  return { subject, status: row.status, createdAt: iso(row.createdAt), counts }
}

// A new managed workspace's row, written `creating` before the object is
// made, so an interrupted creation is found and finished or removed by the
// sweep. The subject quota is checked in the same statement.
async function insertSubject(call: PlatformCall, subject: string): Promise<ManagedWorkspaceRecord> {
  const { platform } = call.caller
  const db = call.rc.env.DB
  const tenant = randomId("tn")
  const inserted = await db
    .prepare(`INSERT INTO managed_workspaces (tenant,platform,subject,subject_hash,status,created_at) SELECT ?,?,?,?,'creating',? WHERE (SELECT COUNT(*) FROM managed_workspaces WHERE platform=? AND status IN ${LIVE})<?`)
    .bind(tenant, platform.id, subject, await platformSubjectHash(platform.id, subject), call.now, platform.id, platform.limits.subjects)
    .run()
    .catch((error: unknown) => {
      if (error instanceof Error && error.message.includes("UNIQUE")) return null
      throw error
    })
  if (inserted !== null && inserted.meta.changes === 0) throw new VaultError("quota_exceeded", `That is past this platform's limit of ${platform.limits.subjects} subjects.`)
  const row = await findSubjectWorkspace(db, platform.id, subject)
  if (!row) throw new VaultError("conflict", "That subject changed while this call ran; try again.")
  return row
}

async function ensureSubject(call: PlatformCall): Promise<PlatformAnswer> {
  const { platform } = call.caller
  if (platform.status === "retiring") throw new VaultError("platform_suspended", "This platform is retiring and takes no new subjects.")
  const subject = subjectOf(call)
  const db = call.rc.env.DB
  const found = await findSubjectWorkspace(db, platform.id, subject)
  // A deleted subject's workspace stays until its purge; the subject gets a new one.
  const row = found !== null && found.status !== "deleted" ? found : await insertSubject(call, subject)
  if (row.status === "deleting" || row.status === "deleted") throw new VaultError("conflict", "That subject is still being deleted; try again once it is.")
  const counts = await ensureSubjectWorkspace(call.rc.env, row.tenant, platformAuth(call))
  if (row.status === "creating") await db.prepare("UPDATE managed_workspaces SET status='active' WHERE tenant=? AND status='creating'").bind(row.tenant).run()
  return { status: row.status === "active" ? 200 : 201, answer: subjectView(subject, { ...row, status: "active" }, counts) }
}

async function getSubject(call: PlatformCall): Promise<PlatformAnswer> {
  const subject = subjectOf(call)
  const row = await findSubjectWorkspace(call.rc.env.DB, call.caller.platform.id, subject)
  if (!row) throw new VaultError("not_found", SUBJECT_NOT_FOUND)
  const counts = row.status === "creating" ? { devices: 0, items: 0, projects: 0 } : await subjectWorkspaceCounts(call.rc.env, row.tenant, platformAuth(call))
  return { status: 200, answer: subjectView(subject, row, counts) }
}

async function removeSubject(call: PlatformCall): Promise<PlatformAnswer> {
  const subject = subjectOf(call)
  const db = call.rc.env.DB
  const row = await findSubjectWorkspace(db, call.caller.platform.id, subject)
  if (!row) throw new VaultError("not_found", SUBJECT_NOT_FOUND)
  if (row.status === "deleted" && row.purgeAfter !== null) return { status: 200, answer: { subject, status: "deleted", purgeAfter: iso(row.purgeAfter) } }
  await db.prepare("UPDATE managed_workspaces SET status='deleting' WHERE tenant=? AND status IN ('creating','active')").bind(row.tenant).run()
  const { purgeAfter } = await removeSubjectWorkspace(call.rc.env, row.tenant, platformAuth(call))
  await db.prepare("UPDATE managed_workspaces SET status='deleted',deleted_at=?,purge_after=? WHERE tenant=? AND status='deleting'").bind(call.now, purgeAfter, row.tenant).run()
  return { status: 200, answer: { subject, status: "deleted", purgeAfter: iso(purgeAfter) } }
}

// Every other subject route is the workspace's own operation. Only the
// audit is read once the subject is being deleted or is deleted.
async function workspaceRoute(call: PlatformCall): Promise<PlatformAnswer> {
  const subject = subjectOf(call)
  const row = await findSubjectWorkspace(call.rc.env.DB, call.caller.platform.id, subject)
  const readable = call.route.name === "audit.read" ? ["active", "deleting", "deleted"] : ["active"]
  if (!row || !readable.includes(row.status)) throw new VaultError("not_found", SUBJECT_NOT_FOUND)
  const value = await callPlatformWorkspace(call.rc.env, row.tenant, `platform.${call.route.name}`, { params: withoutSubject(call.params), query: call.query, body: call.body }, platformAuth(call))
  const statuses: readonly number[] = call.route.status
  const created = z.object({ created: z.boolean() }).safeParse(value)
  const status = statuses.length === 1 ? (statuses[0] ?? 200) : created.success && created.data.created ? 201 : 200
  return { status, answer: value }
}

type PlatformHandler = (call: PlatformCall) => Promise<PlatformAnswer>

// Routes the directory answers; every other route is a workspace operation.
const DIRECTORY_HANDLERS: Partial<Record<PlatformRouteName, PlatformHandler>> = {
  "platform.view": viewPlatform,
  "subjects.list": listSubjects,
  "subjects.ensure": ensureSubject,
  "subjects.get": getSubject,
  "subjects.remove": removeSubject,
  "defaults.put": putDefaults,
  "subjects.removeAll": removeAllSubjects,
}

// The routes answered by a managed workspace's `platform.<name>` operation.
export const PLATFORM_WORKSPACE_ROUTES: readonly PlatformRouteName[] = PLATFORM_ROUTES.map((route) => route.name).filter((name) => DIRECTORY_HANDLERS[name] === undefined)

// The OAuth operations are implemented with the OAuth areas, which list the
// routes they serve; every connection route must be claimed there, and
// nothing else.
export function assertPlatformRoutesClaimed(claimed: readonly PlatformRouteName[]): void {
  const connects = PLATFORM_WORKSPACE_ROUTES.filter((name) => name.startsWith("connects."))
  const unclaimed = connects.filter((name) => !claimed.includes(name))
  const foreign = claimed.filter((name) => !connects.includes(name))
  if (unclaimed.length > 0 || foreign.length > 0) throw new Error(`platform OAuth routes out of step: unclaimed ${unclaimed.join(",") || "none"}, unexpected ${foreign.join(",") || "none"}`)
}

// A `say` that names a CLI command (`mehen ls`) is written for a person at a
// machine, never for a platform.
const NAMES_A_COMMAND = /`mehen\b/

// A platform is never sent to a page or told to run a command: a refusal
// keeps its code, message and a `say` that names no command, and loses any
// link or command.
function platformRefusal(error: unknown): unknown {
  if (!(error instanceof VaultError)) return error
  const { next, ...extra } = error.extra
  const say = next?.say !== undefined && !NAMES_A_COMMAND.test(next.say) ? next.say : undefined
  return new VaultError(error.code, error.message, { ...extra, ...(say !== undefined ? { next: { say } } : {}) })
}

function findPlatformRoute(method: string, pathname: string): { route: Route; params: Record<string, string> } | "method" | null {
  let pathMatched = false
  for (const route of PLATFORM_ROUTES) {
    const params = matchPath(route.path, pathname)
    if (!params) continue
    pathMatched = true
    if (route.method === method) return { route, params }
  }
  return pathMatched ? "method" : null
}

function isWrite(route: Route): boolean {
  return route.method !== "GET"
}

export async function handlePlatformRequest(rc: RequestContext): Promise<Response> {
  const found = findPlatformRoute(rc.request.method, rc.url.pathname)
  if (found === null) throw new VaultError("not_found", "No such route.")
  if (found === "method") return errorResponse({ error: "bad_request", message: "Method not allowed." }, 405)
  const { route } = found
  const now = Date.now()
  const bytes = await readBody(rc.request)
  const caller = await authenticatePlatform(rc.request, await bodyHash(bytes), rc.env.DB, now)
  const vault = rc.env.PLATFORM_VAULT.getByName(caller.platform.id)
  const subjectHash = caller.claims.sub === undefined ? null : await platformSubjectHash(caller.platform.id, caller.claims.sub)
  const record = (outcome: string) => rc.ctx.waitUntil(vault.record(route.name, outcome).catch(() => console.error(JSON.stringify({ at: "platform.record", route: route.name }))))
  try {
    const admitted = await vault.admit({ key: caller.key, jti: caller.claims.jti, iat: caller.claims.iat, subjectHash, write: isWrite(route), decision: route.name === "approvals.decide", limits: caller.platform.limits }, now)
    if (!admitted.ok) {
      const { error, message, ...extra } = admitted.error.vaultError
      throw new VaultError(error, message, extra)
    }
    const call: PlatformCall = { rc, route, caller, params: parseParams(route, found.params), query: parseQuery(route, rc.url), body: parseBody(route, bytes), now }
    const handler = DIRECTORY_HANDLERS[route.name] ?? workspaceRoute
    const { status, answer } = await handler(call)
    const parsed = route.answer.safeParse(answer)
    if (!parsed.success) {
      console.error(JSON.stringify({ at: "platform.answer", route: route.name }))
      throw new VaultError("internal", "Something went wrong inside the vault.")
    }
    record("ok")
    return json(parsed.data, status)
  } catch (error) {
    record(error instanceof VaultError ? error.code : "internal")
    throw platformRefusal(error)
  }
}
