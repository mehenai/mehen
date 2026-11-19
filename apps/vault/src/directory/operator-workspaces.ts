// The operator console's Workspaces view (operator-workspaces.ts in the
// protocol): every workspace on this deployment and one workspace at a
// time, read from the directory, with the little the workspace object
// itself answers its system-only access.operator_view: whether it is
// frozen, its owners, and how many people are unconfirmed. Restoring and
// freezing are operator proposals (operator-proposal-kinds.ts).
//
// Nothing here reaches inside a workspace: no credential, project, member
// beyond the owners' names, machine, ask or audit event.

import { OPERATOR_WORKSPACE_DUMPS_SHOWN, OPERATOR_WORKSPACE_EVENTS_SHOWN, OPERATOR_WORKSPACE_RESTORES_SHOWN, OPERATOR_WORKSPACES_PAGE_SIZE, type OperatorAccountRef, type OperatorManagedWorkspaceRow, type OperatorRestoreView, type OperatorWorkspaceDetail, type OperatorWorkspaceList, type OperatorWorkspaceQuery, type OperatorWorkspaceRow, type OperatorWorkspaceStatus } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { utcDate } from "../vault/areas/vault-backup.ts"
import { type OperatorWorkspaceClient, type OperatorWorkspaceView, operatorWorkspaceClient } from "./operator-workspace-client.ts"
import { namesOf, openOperatorProposal, operatorCount } from "./operator-proposals.ts"
import { operatorRequirementsMissing } from "./operator-requirements.ts"

// What the object answers, or null when it does not: a page still shows
// everything the directory holds.
async function viewOrNull(client: OperatorWorkspaceClient, tenant: string): Promise<OperatorWorkspaceView | null> {
  try {
    return await client.view(tenant)
  } catch {
    console.error(JSON.stringify({ at: "operator.workspace_view", tenant }))
    return null
  }
}

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

// The owners by their account names, or the object's names for theirs.
async function ownerRefs(env: Env, owners: OperatorWorkspaceView["owners"]): Promise<OperatorAccountRef[]> {
  const names = await namesOf(env, owners.map((o) => o.account))
  return owners.map((o) => ({ account: o.account, name: names.get(o.account) ?? o.name }))
}

// ---------------------------------------------------------------- the list

type WorkspaceListRow = { id: string; slug: string; name: string; status: OperatorWorkspaceStatus; created_by: string | null; created_by_name: string | null; created_at: number; members: number }
type ManagedListRow = { tenant: string; status: OperatorManagedWorkspaceRow["status"]; created_at: number; platform: string; platform_slug: string; platform_name: string }

function likePattern(q: string): string {
  return `%${q.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`)}%`
}

function cursorOf(before: string | undefined): { at: number; id: string } | null {
  if (before === undefined) return null
  const [at, id] = before.split(":") as [string, string]
  return { at: Number(at), id }
}

// Newest first, OPERATOR_WORKSPACES_PAGE_SIZE a page. `q` matches a name or
// slug in part, or a workspace id whole.
export async function operatorWorkspaceList(env: Env, query: OperatorWorkspaceQuery, client: OperatorWorkspaceClient = operatorWorkspaceClient(env)): Promise<OperatorWorkspaceList> {
  const filter = query.filter ?? "all", q = query.q ?? "", cursor = cursorOf(query.before)
  const limit = OPERATOR_WORKSPACES_PAGE_SIZE
  if (filter === "managed") {
    const where = [...(q !== "" ? ["(m.tenant=? OR lower(p.slug) LIKE ? ESCAPE '\\' OR lower(p.name) LIKE ? ESCAPE '\\')"] : []), ...(cursor ? ["(m.created_at<? OR (m.created_at=? AND m.tenant<?))"] : [])]
    const rows = await env.DB.prepare(`SELECT m.tenant,m.status,m.created_at,p.id AS platform,p.slug AS platform_slug,p.name AS platform_name FROM managed_workspaces m JOIN platforms p ON p.id=m.platform
      ${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY m.created_at DESC,m.tenant DESC LIMIT ?`)
      .bind(...(q !== "" ? [q, likePattern(q), likePattern(q)] : []), ...(cursor ? [cursor.at, cursor.at, cursor.id] : []), limit + 1).all<ManagedListRow>()
    const page = rows.results.slice(0, limit)
    const last = page.at(-1)
    return {
      filter, q,
      workspaces: page.map((row) => ({ kind: "managed", id: row.tenant, platform: { id: row.platform, slug: row.platform_slug, name: row.platform_name }, status: row.status, createdAt: iso(row.created_at) })),
      next: rows.results.length > limit && last ? `${last.created_at}:${last.tenant}` : null,
    }
  }
  const where = [...(filter !== "all" ? ["w.status=?"] : []), ...(q !== "" ? ["(w.id=? OR lower(w.name) LIKE ? ESCAPE '\\' OR w.slug LIKE ? ESCAPE '\\')"] : []), ...(cursor ? ["(w.created_at<? OR (w.created_at=? AND w.id<?))"] : [])]
  const rows = await env.DB.prepare(`SELECT w.id,w.slug,w.name,w.status,w.created_by,a.name AS created_by_name,w.created_at,
      (SELECT COUNT(*) FROM memberships m WHERE m.workspace=w.id AND m.state IN ('joining','member')) AS members
      FROM workspaces w LEFT JOIN accounts a ON a.id=w.created_by ${where.length > 0 ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY w.created_at DESC,w.id DESC LIMIT ?`)
    .bind(...(filter !== "all" ? [filter] : []), ...(q !== "" ? [q, likePattern(q), likePattern(q)] : []), ...(cursor ? [cursor.at, cursor.at, cursor.id] : []), limit + 1).all<WorkspaceListRow>()
  const page = rows.results.slice(0, limit)
  const views = await Promise.all(page.map((row) => row.status === "active" ? viewOrNull(client, row.id) : Promise.resolve(null)))
  const workspaces: OperatorWorkspaceRow[] = []
  for (const [i, row] of page.entries()) {
    const view = views[i] ?? null
    workspaces.push({ kind: "workspace", id: row.id, slug: row.slug, name: row.name, status: row.status, owners: view === null ? null : await ownerRefs(env, view.owners), members: row.members, createdBy: row.created_by === null ? null : { account: row.created_by, name: row.created_by_name ?? row.created_by }, createdAt: iso(row.created_at) })
  }
  const last = page.at(-1)
  return { filter, q, workspaces, next: rows.results.length > limit && last ? `${last.created_at}:${last.id}` : null }
}

// ---------------------------------------------------------------- one workspace

type WorkspaceRow = { id: string; slug: string; name: string; status: OperatorWorkspaceStatus; created_by: string | null; created_by_name: string | null; created_at: number; delete_after: number | null; display_rev: number }
type RestoreRow = { id: string; source: "pitr" | "dump"; target: string; actor: string; state: OperatorRestoreView["state"]; created_at: number; completed_at: number | null; error: string | null }

// The days a dump restore may name: every good dump of the last 35 days,
// and the first of each month for a year.
function dumpCutoffs(now: number): { daily: string; monthly: string } {
  return { daily: utcDate(now - 35 * 86_400_000), monthly: utcDate(now - 366 * 86_400_000) }
}

export async function operatorWorkspaceDetail(env: Env, id: string, you: string, client: OperatorWorkspaceClient = operatorWorkspaceClient(env), now = Date.now()): Promise<OperatorWorkspaceDetail> {
  const row = await env.DB.prepare("SELECT w.id,w.slug,w.name,w.status,w.created_by,a.name AS created_by_name,w.created_at,w.delete_after,w.display_rev FROM workspaces w LEFT JOIN accounts a ON a.id=w.created_by WHERE w.id=?").bind(id).first<WorkspaceRow>()
  if (!row) throw new VaultError("not_found", "No such workspace.")
  const cutoffs = dumpCutoffs(now)
  const [slugs, roles, lastDump, lastFailure, dumps, restores, events, operators, missing, restore, view] = await Promise.all([
    env.DB.prepare("SELECT slug,retired_at FROM workspace_slugs WHERE workspace=? ORDER BY retired_at DESC,slug").bind(id).all<{ slug: string; retired_at: number }>(),
    env.DB.prepare("SELECT state,role_hint,COUNT(*) AS n FROM memberships WHERE workspace=? AND state IN ('joining','member') GROUP BY state,role_hint").bind(id).all<{ state: "joining" | "member"; role_hint: "owner" | "admin" | "member" | "guest"; n: number }>(),
    env.DB.prepare("SELECT date,bytes,sha256,root_version,attempted_at FROM vault_backup_runs WHERE tenant=? AND outcome='ok' ORDER BY date DESC LIMIT 1").bind(id).first<{ date: string; bytes: number; sha256: string; root_version: number; attempted_at: number }>(),
    env.DB.prepare("SELECT date,error,attempts FROM vault_backup_runs WHERE tenant=? AND outcome='failed' ORDER BY date DESC LIMIT 1").bind(id).first<{ date: string; error: string; attempts: number }>(),
    env.DB.prepare("SELECT date FROM vault_backup_runs WHERE tenant=? AND outcome='ok' AND (date>=? OR (date>=? AND date LIKE '%-01')) ORDER BY date DESC LIMIT ?").bind(id, cutoffs.daily, cutoffs.monthly, OPERATOR_WORKSPACE_DUMPS_SHOWN).all<{ date: string }>(),
    env.DB.prepare("SELECT id,source,target,actor,state,created_at,completed_at,error FROM vault_restore_intents WHERE tenant=? ORDER BY created_at DESC,id DESC LIMIT ?").bind(id, OPERATOR_WORKSPACE_RESTORES_SHOWN).all<RestoreRow>(),
    env.DB.prepare("SELECT id,at,kind,actor,approver,target,details FROM deployment_events WHERE target=? ORDER BY at DESC,id DESC LIMIT ?").bind(id, OPERATOR_WORKSPACE_EVENTS_SHOWN).all<{ id: string; at: number; kind: string; actor: string; approver: string | null; target: string; details: string }>(),
    operatorCount(env),
    operatorRequirementsMissing(env, you, now),
    openOperatorProposal(env, "workspace.restore", id, now),
    row.status === "active" ? viewOrNull(client, id) : Promise.resolve(null),
  ])
  const count = { owner: 0, admin: 0, member: 0, guest: 0 }
  let joining = 0
  for (const r of roles.results) {
    if (r.state === "joining") joining += r.n
    else count[r.role_hint] += r.n
  }
  return {
    you,
    workspace: { id: row.id, slug: row.slug, name: row.name, status: row.status, frozen: view?.frozen ?? null, createdAt: iso(row.created_at), createdBy: row.created_by === null ? null : { account: row.created_by, name: row.created_by_name ?? row.created_by }, deleteAfter: row.delete_after === null ? null : iso(row.delete_after), displayRevision: row.display_rev, slugs: slugs.results.map((s) => ({ slug: s.slug, retiredAt: iso(s.retired_at) })) },
    people: { owners: view === null ? null : await ownerRefs(env, view.owners), roles: count, joining, unconfirmed: view?.unconfirmed ?? null },
    backups: {
      lastDump: lastDump ? { date: lastDump.date, bytes: lastDump.bytes, sha256: lastDump.sha256, rootVersion: lastDump.root_version, at: iso(lastDump.attempted_at) } : null,
      lastFailure: lastFailure && (!lastDump || lastFailure.date > lastDump.date) ? { date: lastFailure.date, error: lastFailure.error, attempts: lastFailure.attempts } : null,
      dumps: dumps.results.map((d) => d.date),
      restores: restores.results.map((r) => ({ id: r.id, source: r.source, target: r.target, actor: r.actor, state: r.state, createdAt: iso(r.created_at), completedAt: r.completed_at === null ? null : iso(r.completed_at), error: r.error })),
    },
    restore,
    operators,
    missing,
    events: events.results.map((e) => ({ id: e.id, at: iso(e.at), kind: e.kind, actor: e.actor, approver: e.approver, target: e.target, details: JSON.parse(e.details) as Record<string, unknown> })),
  }
}
