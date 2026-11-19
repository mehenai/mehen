// The operator console and platform admins (CONSOLE_ROUTES in the protocol
// package): browser routes on a web session, same-origin for every write
// like every account route.
//
// - An account without the operator role gets not_found on every operator
//   route, and an account that does not administer a platform gets
//   not_found on every route of it, with the same answer as a route that
//   does not exist.
// - Every write needs a fresh passkey step-up (five minutes, used once)
//   bound to the exact command; a destructive command, and one that adds a
//   key, also needs the platform's slug typed back.
// - An operator write is refused, saying what is missing, from an account
//   without everything an operator account must have (recovery, two
//   passkeys with a security key, no cooling-off, no pending security
//   change: operator-requirements.ts).
// - A write is planned by operator-plan.ts, the planner the operator script
//   runs, and applied in one batch that first checks the role still holds
//   (for the operator, with every requirement still met),
//   records the platform_events row with actor operator:<account id> or
//   admin:<account id>, and gives that account a notice. A key added also
//   tells every operator account and the platform's other live admins.

import { AdminChangeAnswerSchema, AdminChangeRequestSchema, AdminPlatformListSchema, type AdminPlatformCommand, CONSOLE_ROUTES, SLUG_CONFIRMED_PLATFORM_COMMANDS, OperatorChangeAnswerSchema, OperatorChangeRequestSchema, type OperatorPlatformCommand, OperatorPlatformListSchema, OperatorRegisterRequestSchema, PlatformEventQuerySchema, PlatformSlugSchema, type WorkspaceStepUpAction, WorkspaceStepUpActionSchema, adminStepUpAction, operatorProposalDigest, operatorStepUpAction } from "@mehen/protocol"
import { z } from "zod"
import type { AccountWebSession } from "../directory/account-session.ts"
import type { StepUpProof } from "@mehen/protocol/step-up-proof"
import { currentAccountSession } from "../directory/account-session.ts"
import { accountBatch, accountGuard } from "../directory/account-store.ts"
import { operatorReadySql, operatorRequirementsMissing, requireOperatorReady } from "../directory/operator-requirements.ts"
import { workspaceCreationDefault } from "../directory/workspace-creation.ts"
import { requireAccountStepUp, startAccountStepUp } from "../directory/workspace-stepup.ts"
import type { Env } from "../env.ts"
import { VaultError, json } from "../http.ts"
import { adminPlatformDetail, adminPlatformList, consoleAccess, hasAdministeredPlatforms, isOperator, isPlatformAdmin, operatorPlatformDetail, operatorPlatformList, platformEventPage, readPlatformRowById, readPlatformRowBySlug } from "../platform/console.ts"
import { type PlanIds, type PlatformChange, PlatformInputError, type PlatformPlan, type PlatformRow, newPlanIds, planPlatformChange } from "../platform/operator-plan.ts"
import { removeSubjectWorkspace } from "../platform/workspace-calls.ts"
import type { Route } from "../router.ts"
import { randomId } from "../vault/core.ts"
import { accountBody, accountBrowser, limitWorkspaceStepUp, requireAccount } from "./account.ts"
import type { Handler, RequestContext } from "./context.ts"

// The answer to a console route the account may not open: the same as a
// route that does not exist.
export function hidden(): VaultError {
  return new VaultError("not_found", "No such operation.")
}

export async function operatorAccount(rc: RequestContext): Promise<AccountWebSession> {
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account || !(await isOperator(rc.env, account.account))) throw hidden()
  return account
}

// The platform the address names, or null for a slug that is no platform's,
// including one no platform could have (the router decodes %00 and the like).
async function platformInPath(rc: RequestContext): Promise<PlatformRow | null> {
  const slug = PlatformSlugSchema.safeParse(rc.params.slug)
  return slug.success ? readPlatformRowBySlug(rc.env, slug.data) : null
}

async function adminAccount(rc: RequestContext): Promise<{ account: AccountWebSession; platform: PlatformRow }> {
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) throw hidden()
  const platform = await platformInPath(rc)
  if (!platform || !(await isPlatformAdmin(rc.env, account.account, platform.id))) throw hidden()
  return { account, platform }
}

// Only ever after operatorAccount: the operator is told a slug names no
// platform, the same for one no platform could have.
async function operatorPlatform(rc: RequestContext): Promise<PlatformRow> {
  const platform = await platformInPath(rc)
  if (!platform) throw new VaultError("not_found", "No such platform.")
  return platform
}

function confirmed(command: { command: string; confirm?: string }, slug: string): void {
  if ((SLUG_CONFIRMED_PLATFORM_COMMANDS as readonly string[]).includes(command.command) && command.confirm !== slug) throw new VaultError("bad_request", "Type the platform's slug to confirm.")
}

// A write with no passkey proof at all gets the step-up's own refusal
// before it is planned, so a plan's answer ("no such subject", "that key
// is already registered") never reaches a session without the passkey.
export async function proofSent(rc: RequestContext, account: AccountWebSession, action: WorkspaceStepUpAction, stepUp: StepUpProof | undefined): Promise<void> {
  if (stepUp === undefined) await requireAccountStepUp(rc, account, "-", action, undefined)
}

function eventQuery(rc: RequestContext): string | undefined {
  const parsed = PlatformEventQuerySchema.safeParse(Object.fromEntries(rc.url.searchParams))
  if (!parsed.success) throw new VaultError("bad_request", "That is not a page of this platform's events.")
  return parsed.data.before
}

async function plan(env: Env, change: PlatformChange, platform: PlatformRow | null, ids: PlanIds, now: number): Promise<PlatformPlan> {
  let planned: PlatformPlan | string
  try {
    planned = await planPlatformChange(change, platform, async <T>(sql: string) => (await env.DB.prepare(sql).all<T>()).results, now, ids)
  } catch (error) {
    if (error instanceof PlatformInputError) throw new VaultError("bad_request", error.message)
    throw error
  }
  if (typeof planned === "string") throw new VaultError("conflict", `Nothing changed: ${planned}.`)
  return planned
}

type Notice = { account: string; payload: Record<string, unknown> }

const CHANGED_MEANWHILE = "Nothing changed: the platform changed while this ran. Read it again and retry."

// One batch: the role check, the plan, then the notices, each written only
// once the plan's event is. The first statement of the plan must match. A
// unique slug, key or admin taken between the plan and the batch (two
// writes at once) aborts the whole batch, and is the same refusal.
async function apply(env: Env, planned: PlatformPlan, role: D1PreparedStatement, notices: Notice[], now: number): Promise<D1Result[]> {
  const statements = [
    role,
    ...planned.statements.map((statement) => env.DB.prepare(statement)),
    ...notices.map((notice) => env.DB.prepare("INSERT INTO account_notices(id,account,kind,payload,at) SELECT ?,?,'workspace',?,? WHERE EXISTS (SELECT 1 FROM platform_events WHERE id=?)").bind(randomId("ntc"), notice.account, JSON.stringify(notice.payload), now, planned.event)),
  ]
  let results: D1Result[]
  try {
    results = await accountBatch(env, statements)
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) throw new VaultError("conflict", CHANGED_MEANWHILE)
    throw error
  }
  if ((results[1]?.results.length ?? 0) === 0) throw new VaultError("conflict", CHANGED_MEANWHILE)
  return results
}

// The role still held, and every requirement of an operator account still
// met (operator-requirements.ts).
export function operatorRole(env: Env, account: string, now: number): D1PreparedStatement {
  return accountGuard(env, `EXISTS (SELECT 1 FROM accounts a WHERE a.id=? AND a.status='active' AND a.is_operator=1 AND ${operatorReadySql("a")})`, [account, now])
}

function adminRole(env: Env, account: string, platform: string): D1PreparedStatement {
  return accountGuard(env, "EXISTS (SELECT 1 FROM platform_admins pa JOIN accounts a ON a.id=pa.account WHERE pa.platform=? AND pa.account=? AND pa.removed_at IS NULL AND a.status='active')", [platform, account])
}

function operatorChange(command: OperatorPlatformCommand, slug: string, actor: string): PlatformChange {
  switch (command.command) {
    case "suspend":
    case "delete-subjects":
    case "remove":
      return { command: command.command, slug, reason: command.reason, actor }
    case "resume":
      return { command: "resume", slug, actor }
    case "rotate-key":
      return { command: "rotate-key", slug, key: command.key, overlapHours: command.overlapHours, actor }
    case "revoke-key":
      return { command: "revoke-key", slug, key: command.key, actor }
    case "limits":
      return { command: "limits", slug, limits: command.limits, actor }
    case "retire":
      return { command: "retire", slug, afterDays: command.afterDays, actor }
    case "add-admin":
    case "remove-admin":
      return { command: command.command, slug, account: command.account, actor }
  }
}

function adminChange(command: AdminPlatformCommand, slug: string, actor: string): PlatformChange {
  switch (command.command) {
    case "defaults":
      return { command: "defaults", slug, defaults: command.defaults, revision: command.revision, actor }
    case "rotate-key":
      return { command: "rotate-key", slug, key: command.key, overlapHours: command.overlapHours, actor }
    case "revoke-key":
      return { command: "revoke-key", slug, key: command.key, actor }
    case "delete-subject":
      return { command: "delete-subject", slug, subject: command.subject, actor }
  }
}

// Adding a key makes whoever holds its private half the platform until it
// is revoked, so besides the account that added it, every operator account
// and every live admin of the platform is told.
async function keyAddedNotices(env: Env, platform: string, actorAccount: string, payload: Record<string, unknown>): Promise<Notice[]> {
  const rows = await env.DB.prepare("SELECT id AS account FROM accounts WHERE is_operator=1 AND status='active' UNION SELECT account FROM platform_admins WHERE platform=? AND removed_at IS NULL ORDER BY account").bind(platform).all<{ account: string }>()
  return rows.results.filter((row) => row.account !== actorAccount).map((row) => ({ account: row.account, payload }))
}

async function liveAdmins(env: Env, platform: string): Promise<string[]> {
  return (await env.DB.prepare("SELECT account FROM platform_admins WHERE platform=? AND removed_at IS NULL ORDER BY added_at,account").bind(platform).all<{ account: string }>()).results.map((row) => row.account)
}

async function changedPlatform(env: Env, id: string): Promise<PlatformRow> {
  const row = await readPlatformRowById(env, id)
  if (!row) throw new Error("platform gone after a change")
  return row
}

// After an admin's delete-subject is recorded, the subject is deleted at
// once, as the platform's own route does, and the workspace's audit, which
// the platform reads until the purge, names the admin; if that fails the
// cron finishes it, as the directory.
async function deleteSubjectNow(env: Env, tenant: string, actor: string, now: number): Promise<void> {
  try {
    const { purgeAfter } = await removeSubjectWorkspace(env, tenant, { kind: "system", reason: "platform admin console", actor })
    await env.DB.prepare("UPDATE managed_workspaces SET status='deleted',deleted_at=?,purge_after=? WHERE tenant=? AND status='deleting'").bind(now, purgeAfter, tenant).run()
  } catch {
    console.error(JSON.stringify({ at: "console.delete_subject", tenant }))
  }
}

export const consoleRoutes: Route<Handler>[] = [
  accountBrowser("GET", CONSOLE_ROUTES.access, async (rc) => json(await consoleAccess(rc.env, (await requireAccount(rc)).account))),

  // ---------------------------------------------------------------- the operator

  accountBrowser("POST", CONSOLE_ROUTES.operatorStepUp, async (rc) => {
    const account = await operatorAccount(rc)
    const { action } = await accountBody(rc, z.strictObject({ action: WorkspaceStepUpActionSchema }))
    if (action.type !== "platform.operate" && action.type !== "operator.propose" && action.type !== "operator.approve" && action.type !== "operator.break_glass_link") throw new VaultError("bad_request", "That action does not belong to this scope.")
    // Resigning your own role only removes power, so it needs none of an
    // operator account's requirements; every other change does.
    if (action.type !== "operator.propose" || action.digest !== (await operatorProposalDigest({ kind: "operator.resign", target: account.account, params: {} }))) await requireOperatorReady(rc.env, account.account)
    await limitWorkspaceStepUp(rc, account.account)
    return json(await startAccountStepUp(rc.env, account, "-", action))
  }),
  accountBrowser("GET", CONSOLE_ROUTES.operatorPlatforms, async (rc) => {
    const account = await operatorAccount(rc)
    return json(OperatorPlatformListSchema.parse({ platforms: await operatorPlatformList(rc.env), workspaceCreation: await workspaceCreationDefault(rc.env), missing: await operatorRequirementsMissing(rc.env, account.account) }))
  }),
  accountBrowser("POST", CONSOLE_ROUTES.operatorPlatforms, async (rc) => {
    const account = await operatorAccount(rc)
    const { command, stepUp } = await accountBody(rc, OperatorRegisterRequestSchema)
    const actor = `operator:${account.account}`
    const now = Date.now()
    const ids = newPlanIds()
    await requireOperatorReady(rc.env, account.account, now)
    confirmed(command, command.slug)
    const action = await operatorStepUpAction(command.slug, null, command)
    await proofSent(rc, account, action, stepUp)
    const planned = await plan(rc.env, { command: "register", slug: command.slug, name: command.name, key: command.key, limits: command.limits, actor }, await readPlatformRowBySlug(rc.env, command.slug), ids, now)
    await requireAccountStepUp(rc, account, "-", action, stepUp)
    const payload = { change: "platform", command: "register", platform: { id: ids.platform, slug: command.slug }, by: actor, key: ids.key }
    await apply(rc.env, planned, operatorRole(rc.env, account.account, now), [{ account: account.account, payload }, ...(await keyAddedNotices(rc.env, ids.platform, account.account, payload))], now)
    return json(OperatorChangeAnswerSchema.parse({ done: planned.done, platform: await operatorPlatformDetail(rc.env, await changedPlatform(rc.env, ids.platform)) }), 201)
  }),
  accountBrowser("GET", CONSOLE_ROUTES.operatorPlatform, async (rc) => {
    await operatorAccount(rc)
    return json(await operatorPlatformDetail(rc.env, await operatorPlatform(rc)))
  }),
  accountBrowser("POST", CONSOLE_ROUTES.operatorPlatform, async (rc) => {
    const account = await operatorAccount(rc)
    const { command, stepUp } = await accountBody(rc, OperatorChangeRequestSchema)
    const platform = await operatorPlatform(rc)
    const now = Date.now()
    await requireOperatorReady(rc.env, account.account, now)
    confirmed(command, platform.slug)
    const actor = `operator:${account.account}`
    const ids = newPlanIds()
    const action = await operatorStepUpAction(platform.slug, platform.id, command)
    await proofSent(rc, account, action, stepUp)
    const planned = await plan(rc.env, operatorChange(command, platform.slug, actor), platform, ids, now)
    await requireAccountStepUp(rc, account, "-", action, stepUp)
    const ref = { id: platform.id, slug: platform.slug }
    const payload = { change: "platform", command: command.command, platform: ref, by: actor, ...(command.command === "rotate-key" ? { key: ids.key } : {}) }
    const notices: Notice[] = [{ account: account.account, payload }]
    if (command.command === "rotate-key") notices.push(...(await keyAddedNotices(rc.env, platform.id, account.account, payload)))
    if (command.command === "add-admin" || command.command === "remove-admin") notices.push({ account: command.account, payload: { change: "platform_admin", admin: command.command === "add-admin", platform: ref, by: actor } })
    // Removing a platform ends every admin it has, and each is told so.
    if (command.command === "remove") for (const admin of await liveAdmins(rc.env, platform.id)) notices.push({ account: admin, payload: { change: "platform_admin", admin: false, platform: ref, by: actor } })
    await apply(rc.env, planned, operatorRole(rc.env, account.account, now), notices, now)
    return json(OperatorChangeAnswerSchema.parse({ done: planned.done, platform: await operatorPlatformDetail(rc.env, await changedPlatform(rc.env, platform.id)) }))
  }),
  accountBrowser("GET", CONSOLE_ROUTES.operatorEvents, async (rc) => {
    await operatorAccount(rc)
    return json(await platformEventPage(rc.env, (await operatorPlatform(rc)).id, eventQuery(rc)))
  }),

  // ---------------------------------------------------------------- a platform's admins

  accountBrowser("GET", CONSOLE_ROUTES.adminPlatforms, async (rc) => {
    const account = await currentAccountSession(rc.request, rc.env)
    if (!account || !(await hasAdministeredPlatforms(rc.env, account.account))) throw hidden()
    return json(AdminPlatformListSchema.parse({ platforms: await adminPlatformList(rc.env, account.account) }))
  }),
  accountBrowser("POST", CONSOLE_ROUTES.adminStepUp, async (rc) => {
    const { account, platform } = await adminAccount(rc)
    const { action } = await accountBody(rc, z.strictObject({ action: WorkspaceStepUpActionSchema }))
    if (action.type !== "platform.administer" || action.platform !== platform.slug || action.platformId !== platform.id) throw new VaultError("bad_request", "That action does not belong to this scope.")
    await limitWorkspaceStepUp(rc, account.account)
    return json(await startAccountStepUp(rc.env, account, "-", action))
  }),
  accountBrowser("GET", CONSOLE_ROUTES.adminPlatform, async (rc) => {
    const { platform } = await adminAccount(rc)
    return json(await adminPlatformDetail(rc.env, platform))
  }),
  accountBrowser("POST", CONSOLE_ROUTES.adminPlatform, async (rc) => {
    const { account, platform } = await adminAccount(rc)
    const { command, stepUp } = await accountBody(rc, AdminChangeRequestSchema)
    confirmed(command, platform.slug)
    const actor = `admin:${account.account}`
    const now = Date.now()
    const action = await adminStepUpAction(platform.slug, platform.id, command)
    // Deleting a subject is planned only after the passkey: its plan looks
    // the typed subject up, and whether one exists is not the session's to
    // learn. A typo costs a passkey. Every other plan tells only what an
    // admin reads anyway, so it is checked first and a refusal costs none.
    if (command.command === "delete-subject") await requireAccountStepUp(rc, account, "-", action, stepUp)
    else await proofSent(rc, account, action, stepUp)
    const ids = newPlanIds()
    const planned = await plan(rc.env, adminChange(command, platform.slug, actor), platform, ids, now)
    if (command.command !== "delete-subject") await requireAccountStepUp(rc, account, "-", action, stepUp)
    const payload = { change: "platform", command: command.command, platform: { id: platform.id, slug: platform.slug }, by: actor, ...(command.command === "rotate-key" ? { key: ids.key } : {}) }
    const notices: Notice[] = [{ account: account.account, payload }]
    if (command.command === "rotate-key") notices.push(...(await keyAddedNotices(rc.env, platform.id, account.account, payload)))
    const results = await apply(rc.env, planned, adminRole(rc.env, account.account, platform.id), notices, now)
    if (command.command === "delete-subject") {
      const tenant = z.object({ tenant: z.string() }).parse(results[1]?.results[0]).tenant
      await deleteSubjectNow(rc.env, tenant, actor, now)
    }
    if (command.command === "defaults") {
      const audit = { actor, action: "defaults.put", detail: { revision: platform.defaults_rev + 1, by: { admin: account.account } } }
      await rc.env.PLATFORM_VAULT.getByName(platform.id).audit(audit, now).catch(() => console.error(JSON.stringify({ at: "console.defaults.audit", platform: platform.id })))
    }
    return json(AdminChangeAnswerSchema.parse({ done: planned.done, platform: await adminPlatformDetail(rc.env, await changedPlatform(rc.env, platform.id)) }))
  }),
  accountBrowser("GET", CONSOLE_ROUTES.adminEvents, async (rc) => {
    const { platform } = await adminAccount(rc)
    return json(await platformEventPage(rc.env, platform.id, eventQuery(rc)))
  }),
]
