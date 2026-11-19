import { env } from "cloudflare:workers"
import { applyD1Migrations } from "cloudflare:test"
import { expect, it } from "vitest"
import { resetWorkspaceDatabase } from "./workspace-fixtures.ts"

it("fresh-start schema has no legacy or adoption tables and no inferred workspace creation right", async () => {
 const db = env.MIGRATION_DB
 await resetWorkspaceDatabase(db)
 await applyD1Migrations(db, env.TEST_LEGACY_MIGRATIONS)
 await db.batch([
  db.prepare("INSERT INTO tenants(id,name,created_at) VALUES ('tn_legacy','Old tenant',1)"),
  db.prepare("INSERT INTO members(id,tenant,role,name,created_at) VALUES ('mem_legacy','tn_legacy','owner','Old owner',1)"),
  db.prepare("INSERT INTO passkeys(credential_id,member,public_key,counter,created_at) VALUES ('legacy-passkey','mem_legacy',X'0102',0,1)"),
  db.prepare("INSERT INTO web_sessions(token_hash,member,created_at,expires_at,last_seen_at) VALUES ('old-session','mem_legacy',1,9999999999999,1)"),
  db.prepare("INSERT INTO invites(code_hash,tenant,role,created_at,expires_at) VALUES ('old-invite','tn_legacy','owner',1,9999999999999)"),
 ])
 await applyD1Migrations(db, env.TEST_MIGRATIONS)
 await applyD1Migrations(db, env.TEST_MIGRATIONS)
 const tables = (await db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all<{ name: string }>()).results.map((r) => r.name)
 for (const forbidden of ["members", "tenants", "invites", "security_notices", "legacy_members", "legacy_tenants", "legacy_member_accounts", "operator_intents"]) expect(tables).not.toContain(forbidden)
 for (const table of ["accounts", "workspaces", "memberships", "passkeys", "web_sessions", "enrolments", "account_security_transitions", "app_gate_codes"]) expect((await db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())?.n).toBe(0)
 await db.prepare("INSERT INTO accounts(id,name,created_at) VALUES ('acc_first','First account',1)").run()
 expect(await db.prepare("SELECT can_create_workspaces,recovery_setup_at,recovery_setup_kind FROM accounts").first()).toEqual({ can_create_workspaces: 0, recovery_setup_at: null, recovery_setup_kind: null })
})

it("cutover account, workspace, enrolment, OAuth and OIDC constraints refuse illegal rows", async () => {
 const db = env.MIGRATION_DB
 await resetWorkspaceDatabase(db)
 await applyD1Migrations(db, env.TEST_MIGRATIONS)
 await db.prepare("INSERT INTO accounts(id,name,created_at) VALUES ('acc_seed','Seed',1)").run()
 await db.prepare("INSERT INTO workspaces(id,slug,name,status,created_at) VALUES ('tn_seed','seed','Seed','active',1)").run()
 await db.prepare("INSERT INTO workspace_slugs(slug,workspace,retired_at) VALUES ('retired','tn_seed',1)").run()
 type Row = Record<string, string | number | null>
 const insert = (table: string, row: Row) => db.prepare(`INSERT INTO ${table}(${Object.keys(row).join(",")}) VALUES (${Object.keys(row).map(() => "?").join(",")})`).bind(...Object.values(row)).run()
 const legal: Record<string, Row> = {
  accounts: { id: "acc_valid", name: "Valid", created_at: 1 },
  workspaces: { id: "tn_valid", slug: "valid", name: "Valid", status: "active", created_at: 1 },
  workspace_slugs: { slug: "alias", workspace: "tn_seed", retired_at: 1 },
  memberships: { id: "mem_valid", account: "acc_seed", workspace: "tn_seed", state: "member", role_hint: "member", updated_at: 1 },
  enrolments: { id: "enr_valid", code_hash: "h", jwk: "{}", thumbprint: "t", name: "Valid", backend: "software", status: "pending", created_at: 1, expires_at: 2, workspace_intent: "seed", owner_intent: '{"kind":"self"}', start_at: 1, start_client_label: "CLI", pending_state: "pending_owner_acceptance" },
  oauth_states: { state_hash: "s", tenant: "tn_seed", connect: "c", expires_at: 2, account: "acc_seed", membership: "mem_seed", initiating_session: "ses_seed", security_epoch: 0, intent: "create" },
  oidc_flows: { state_hash: "s", cookie_hash: "c", provider: "google", purpose: "signin", nonce: "n", pkce_verifier: "p", created_at: 1, expires_at: 2 },
  oidc_results: { id: "r", cookie_hash: "c", provider: "google", issuer: "https://accounts.google.com", subject: "s", email: "a@example.com", email_verified: 1, purpose: "signin", created_at: 1, expires_at: 2 },
 }
 const illegal: [string, Row][] = [
  ["accounts", { restricted_until: 2 }], ["accounts", { restricted_reason: "recovery" }],
  ["accounts", { recovery_setup_at: 1 }], ["accounts", { recovery_setup_kind: "codes" }],
  ["accounts", { status: "deleted" }], ["accounts", { deleted_at: 1 }],
  ["workspaces", { id: null }], ["workspace_slugs", { slug: null }], ["memberships", { id: null }], ["workspaces", { id: "wrong_prefix" }], ["workspaces", { id: "tn_!" }],
  ["workspaces", { status: "deleting" }], ["workspaces", { slug: "retired" }],
  ["workspace_slugs", { slug: "seed" }], ["memberships", { id: "wrong_prefix" }], ["memberships", { id: "mem_!" }],
  ["enrolments", { owner_intent: "invalid" }], ["enrolments", { pending_state: null }],
  ["enrolments", { status: "active" }],
 ]
 for (const table of ["workspaces", "workspace_slugs"]) for (const slug of ["legacy-any", "has--dash", "Upper", "-bad", "bad-", "x", "with space", "a".repeat(41)]) illegal.push([table, { slug }])
 for (const key of ["workspace_intent", "owner_intent", "start_at", "start_client_label"]) illegal.push(["enrolments", { [key]: null }])
 for (const key of ["acceptance_digest", "accepted_by_account", "accepted_by_member", "accepted_at", "admission_digest", "admitted_by_account", "admitted_at"]) illegal.push(["enrolments", { [key]: key.endsWith("account") ? "acc_seed" : key.endsWith("_at") ? 1 : "partial" }])
 for (const key of ["account", "membership", "initiating_session", "security_epoch", "intent"]) illegal.push(["oauth_states", { [key]: null }])
 for (const table of ["oidc_flows", "oidc_results"]) {
  for (const purpose of ["gate", "link", "invite"]) illegal.push([table, { purpose }])
  for (const key of ["workspace", "rule_revision", "gate_generation"]) illegal.push([table, { purpose: "gate", workspace: "tn_seed", rule_revision: 1, gate_generation: 1, [key]: null }])
  for (const key of ["account", "session", "security_epoch"]) illegal.push([table, { purpose: "link", account: "acc_seed", session: "ses_seed", security_epoch: 0, [key]: null }])
  illegal.push([table, { app_session_hash: "app" }], [table, { app_pkce_challenge: "pkce" }])
 }
 for (const [table, patch] of illegal) await expect(insert(table, { ...legal[table], ...patch }), `${table}: ${JSON.stringify(patch)}`).rejects.toThrow()
 for (const [table, row] of Object.entries(legal)) await expect(insert(table, row), table).resolves.toBeDefined()
 for (const table of ["oidc_flows", "oidc_results"]) for (const [purpose, bindings] of [
  ["gate", { workspace: "tn_seed", rule_revision: 1, gate_generation: 1 }],
  ["link", { account: "acc_seed", session: "ses_seed", security_epoch: 0 }],
  ["invite", { invite_hash: "invite" }],
 ] as [string, Row][]) await expect(insert(table, { ...legal[table], ...(table === "oidc_flows" ? { state_hash: purpose } : { id: purpose }), purpose, ...bindings })).resolves.toBeDefined()
 await expect(db.prepare("UPDATE workspaces SET slug='retired' WHERE id='tn_seed'").run()).rejects.toThrow()
 await expect(db.prepare("UPDATE workspace_slugs SET slug='seed' WHERE slug='retired'").run()).rejects.toThrow()
})
