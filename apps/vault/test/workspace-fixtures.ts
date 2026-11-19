// Fresh-schema D1 fixtures. The legacy shared fixtures stay separate.
import { env } from "cloudflare:workers"
import { applyD1Migrations } from "cloudflare:test"
import type { Share, WorkspaceDeviceScope, WorkspaceRole } from "@mehen/protocol"
import type { Env } from "../src/env.ts"
import type { AccessDevice, AccessMember, AccessPrincipal, AccessState } from "../src/vault/access.ts"
import { SESSION_COOKIE, sha256Text } from "../src/directory/session.ts"

export const WORKSPACE_FULL_SCOPE: WorkspaceDeviceScope = { tags: [], projects: [], maxEnvironment: "protected", modes: ["relay", "sign", "mint", "placeholder", "lease"], privateCredentials: false }
export function workspaceAccessState(now = Date.now()): AccessState {
 const members: AccessMember[] = (["owner", "admin", "member", "guest"] as WorkspaceRole[]).map((role) => ({ id: `mem_${role}`, account: `acc_${role}`, name: role, status: "active", standing: { identityRule: null, checkSequence: 0, effectiveRole: role, pendingRole: null, restriction: null, identityGate: { covered: false, admitted: true, checkedAt: null }, transitionPending: false, identityRuleRev: 1, gateGeneration: 1 }, canCreateWorkspaces: role === "owner" }))
 members.push({ ...structuredClone(members[2] as AccessMember), id: "mem_kim", account: "acc_kim", name: "Kim" })
 const share = (id: string, project: string, subject: Share["subject"], level: Share["level"], protectedTick = false): Share => ({ id, project, subject, level, protected: protectedTick, expiresAt: null })
 const refs = (item: string, home: import("@mehen/protocol").CredentialHome) => [{ variable: "TOKEN", field: "key", item, home, revision: 1 }]
 return { accessRev: 1, members, teams: [{ id: "tm_engineering", name: "Engineering", members: ["mem_member"] }, { id: "tm_service", name: "Service", members: [] }], shares: [
  share("shr_direct", "prj_a", { kind: "member", member: "mem_member" }, "edit"),
  share("shr_team", "prj_a", { kind: "team", team: "tm_engineering" }, "use", true),
  share("shr_guest", "prj_a", { kind: "member", member: "mem_guest" }, "edit", true),
  share("shr_service", "prj_a", { kind: "team", team: "tm_service" }, "use"),
  share("shr_kim", "prj_a", { kind: "member", member: "mem_kim" }, "manage"),
 ], projects: ["prj_a", "prj_b"].map((id) => ({ id, slug: id.replace("prj_", "project-"), environments: [
  { name: "dev", protected: false, fourEyes: false, revision: 1, protectionRevision: 1, fences: [], references: refs("itm_workspace", { kind: "workspace" }) },
  { name: "prod", protected: true, fourEyes: true, revision: 1, protectionRevision: 1, fences: [], references: id === "prj_a" ? refs("itm_project", { kind: "project", project: "prj_a" }) : [] },
  { name: "staging", protected: true, fourEyes: false, revision: 1, protectionRevision: 1, fences: [], references: [] },
 ] })), credentials: [ { id: "itm_workspace", home: { kind: "workspace" }, tags: [] }, { id: "itm_project", home: { kind: "project", project: "prj_a" }, tags: [] }, ...["owner", "admin", "member", "guest", "kim"].map((role) => ({ id: `itm_${role}`, home: { kind: "member" as const, member: `mem_${role}` }, tags: [] })) ], devices: [...members.map((m): AccessDevice => ({ id: `dev_${m.id.slice(4)}`, status: "active", owner: { kind: "member", id: m.id }, scope: structuredClone(WORKSPACE_FULL_SCOPE) })), { id: "dev_service", status: "active", owner: { kind: "team", id: "tm_service" }, scope: structuredClone(WORKSPACE_FULL_SCOPE) }] }

}
export function accessMember(state: AccessState, role: string): AccessPrincipal {
 const m = state.members.find((m) => m.id === `mem_${role}`)
 if (!m) throw new Error(`Missing fixture member ${role}`)
 return { kind: "member", account: m.account, memberId: m.id, session: `ses_${role}`, securityEpoch: 0, sessionCheck: m.standing.identityGate.checkedAt === null ? null : { id: `chk_${role}`, identityRuleRev: m.standing.identityRuleRev, gateGeneration: m.standing.gateGeneration, checkSequence: 1, succeededAt: new Date(m.standing.identityGate.checkedAt).toISOString(), expiresAt: new Date(m.standing.identityGate.checkedAt + 86_400_000).toISOString() } }
}
export type WorkspaceTestFixture = { env: Env; state: AccessState; cookie: string; workspaces: { personal: string; work: string }; account: string; session: string; personalMember: string; pendingJoin: string }
export async function createWorkspaceFixture(): Promise<WorkspaceTestFixture> {
 const db = env.WORKSPACE_DB
 await resetWorkspaceDatabase(db)
 await applyD1Migrations(db, env.TEST_MIGRATIONS)
 const now = Date.now()
 const state = workspaceAccessState(now)
 const account = "acc_owner"
 const session = "ses_workspace_fixture"
 const personal = "tn_Alpha123456"
 const work = "tn_Beta1234567"
 const token = "workspace-fixture-token"
 const statements = []
 for (const m of state.members) statements.push(db.prepare("INSERT INTO accounts(id,name,created_at) VALUES (?,?,?)").bind(m.account,m.name,now))
 statements.push(db.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,'alex','Personal','active',?,?),(?,'northwind','Work','active',?,?)").bind(personal,account,now,work,account,now))
 statements.push(db.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES ('mem_personal',?,?,'member','owner',?),('mem_joining','acc_member',?,'joining','member',?)").bind(account,personal,now,personal,now))
 for (const m of state.members) statements.push(db.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES (?,?,?,'member',?,?)").bind(m.id,m.account,work,m.standing.effectiveRole,now))
 statements.push(db.prepare("INSERT INTO web_sessions(token_hash,id,account,created_at,expires_at,last_seen_at,kind,method,client) VALUES (?,?,?,?,?,?,'web','passkey','Test browser')").bind(await sha256Text(token),session,account,now,now+2_592_000_000,now))
 await db.batch(statements)
 return { env: { ...env, DB: db }, state, cookie: `${SESSION_COOKIE}=${token}`, workspaces: { personal, work }, account, session, personalMember: "mem_personal", pendingJoin: "mem_joining" }
}

// Pool storage persists between tests. Only isolated workspace-test bindings
// enter this reset; the deployable legacy DB binding must never be passed.
export async function resetWorkspaceDatabase(db: D1Database): Promise<void> {
 const tables = await db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*'").all<{ name: string }>()
 if (tables.results.some((t) => !/^[a-z_][a-z0-9_]*$/.test(t.name))) throw new Error("Unexpected fixture table name")
 await db.batch([db.prepare("PRAGMA defer_foreign_keys=true"), ...tables.results.map((t) => db.prepare(`DROP TABLE ${t.name}`))])
}
