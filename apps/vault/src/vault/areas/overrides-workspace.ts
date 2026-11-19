import { type CredentialHome, type WorkspaceStepUpAction } from "@mehen/protocol"
import { EnvName, Slug, VarName } from "@mehen/protocol/api"
import { KINDS } from "@mehen/protocol/kinds"
import { z } from "zod"
import { VaultError } from "../../http.ts"
import { type Area, type VaultContext, one, rows } from "../core.ts"
import { can } from "../access.ts"
import type { OverrideResolutionHook } from "../services.ts"
import { parseOpInput } from "./approvals.ts"
import { items } from "./items.ts"
import { secretLikeness } from "./projects.ts"
import { accessState, eligibilityState, authorise, registerAccessChangeHook, registerOffboardingHook, requireStepUp, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

const Id = z.string().min(1).max(64)
export const OverrideSource = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("plain"), value: z.string().max(4096) }),
  z.strictObject({ kind: z.literal("item"), item: Slug, field: z.string().min(1).max(64) }),
])
export const OverrideInput = z.strictObject({ project: Id, environment: EnvName, variable: VarName, source: OverrideSource.nullable() })
type OverrideInput = z.infer<typeof OverrideInput>
export type MachineOverride = { environment: string; variable: string; source: { kind: "plain" } | { kind: "item"; item: string; field: string } }
type OverrideRow = { member: string; project: string; env: string; name: string; item: string | null; field: string | null; plain: string | null; updated_at: number }

function missing(): never { throw new VaultError("not_found", "No such object.") }
function ownMember(ctx: VaultContext, invocation: WorkspaceInvocationContext, project: string): string {
  const decision = authorise(ctx, invocation, { type: "project.read" }, { project }, ctx.now())
  if (decision.principal.kind !== "member") throw new VaultError("forbidden", "Only a person can choose personal overrides.")
  return decision.principal.memberId
}
function actionFor(ctx: VaultContext, invocation: WorkspaceInvocationContext, input: OverrideInput): Extract<WorkspaceStepUpAction, { type: "override.set" }> {
  const member = ownMember(ctx, invocation, input.project)
  const state = eligibilityState(ctx, invocation)
  const item = input.source?.kind === "item" ? items.getItem(ctx, input.source.item) : null
  const credential = item ? state.credentials.find(c => c.id === item.id) : null
  // Never distinguish a foreign private source from an absent id.
  if (input.source?.kind === "item" && (!credential || credential.home.kind !== "member" || credential.home.member !== member)) missing()
  authorise(ctx, invocation, { type: "override.set" }, { project: input.project, environment: input.environment, ...(credential ? { credential: credential.id } : {}) }, ctx.now())
  if (!one(ctx.sql.exec("SELECT 1 FROM vars WHERE project=? AND env=? AND name=?", input.project, input.environment, input.variable))) missing()
  if (input.source?.kind === "item") {
    if (!item || !KINDS[item.kind].fields.some(f => input.source?.kind === "item" && f.name === input.source.field)) missing()
  } else if (input.source && secretLikeness(input.source.value)) throw new VaultError("bad_request", "This value looks like a secret; store it as a credential instead.")
  return { type: "override.set", ...input, source: input.source?.kind === "item" ? { ...input.source, item: credential!.id } : input.source }
}
function ownOverrides(ctx: VaultContext, member: string, project: string) {
  return { overrides: rows(ctx.sql.exec<OverrideRow & { slug: string | null }>("SELECT o.*,i.slug FROM overrides o LEFT JOIN items i ON i.id=o.item WHERE o.member=? AND o.project=? ORDER BY o.env,o.name", member, project)).map(row => ({ environment: row.env, variable: row.name, source: row.item === null ? { kind: "plain" as const, value: row.plain! } : { kind: "item" as const, item: row.slug!, field: row.field! }, updatedAt: new Date(row.updated_at).toISOString() })) }
}

export const overridesArea: Area = {
  name: "overrides",
  migrations: [`CREATE TABLE overrides (
    member TEXT NOT NULL, project TEXT NOT NULL, env TEXT NOT NULL, name TEXT NOT NULL,
    item TEXT, field TEXT, plain TEXT, updated_at INTEGER NOT NULL,
    PRIMARY KEY(member,project,env,name),
    FOREIGN KEY(project,env,name) REFERENCES vars(project,env,name) ON DELETE CASCADE,
    CHECK ((item IS NOT NULL AND field IS NOT NULL AND plain IS NULL) OR (item IS NULL AND field IS NULL AND plain IS NOT NULL))
  ); CREATE INDEX overrides_item ON overrides(item);`],
  workspaceOps: {
    "overrides.machine": { auth: ["device"], handler(ctx, principal, raw, invocation) {
      const { project } = parseOpInput(z.strictObject({ project: Id }), raw)
      authorise(ctx, invocation, { type: "project.read" }, { project }, ctx.now())
      if (principal.kind !== "device") missing()
      const state = accessState(ctx), device = state.devices.find(d => d.id === principal.deviceId)
      if (!device || device.owner.kind !== "member") return { overrides: [] }
      const environments = state.projects.find(p => p.id === project)?.environments ?? []
      const overrides = rows(ctx.sql.exec<OverrideRow>("SELECT * FROM overrides WHERE member=? AND project=? ORDER BY env,name", device.owner.id, project)).flatMap<MachineOverride>(row => {
        const environment = environments.find(e => e.name === row.env)
        if (!environment || environment.protected) return []
        if (row.item === null) return [{ environment: row.env, variable: row.name, source: { kind: "plain" as const } }]
        if (!device.scope.privateCredentials || !can(state, principal, { type: "item.read" }, { credential: row.item }, ctx.now()).allowed) return []
        const item = one(ctx.sql.exec<{ slug: string }>("SELECT slug FROM items WHERE id=? AND home_kind='member' AND home_id=?", row.item, device.owner.id))
        return item ? [{ environment: row.env, variable: row.name, source: { kind: "item" as const, item: item.slug, field: row.field! } }] : []
      })
      return { overrides }
    } },
    "overrides.list": { auth: ["account"], handler(ctx, _principal, raw, invocation) {
      const { project } = parseOpInput(z.strictObject({ project: Id }), raw)
      return ownOverrides(ctx, ownMember(ctx, invocation, project), project)
    } },
    "overrides.action": { auth: ["account"], handler(ctx, _principal, raw, invocation) {
      return actionFor(ctx, invocation, parseOpInput(OverrideInput, raw))
    } },
    "overrides.set": { auth: ["account"], handler(ctx, _principal, raw, invocation) {
      const input = parseOpInput(OverrideInput, raw)
      return ctx.storage.transactionSync(() => {
        const action = actionFor(ctx, invocation, input)
        const decision = authorise(ctx, invocation, { type: "override.set" }, { project: input.project, environment: input.environment, ...(action.source?.kind === "item" ? { credential: action.source.item } : {}) }, ctx.now())
        requireStepUp(ctx, decision, action, invocation)
        const member = ownMember(ctx, invocation, input.project)
        if (input.source === null) ctx.sql.exec("DELETE FROM overrides WHERE member=? AND project=? AND env=? AND name=?", member, input.project, input.environment, input.variable)
        else ctx.sql.exec(`INSERT INTO overrides(member,project,env,name,item,field,plain,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(member,project,env,name) DO UPDATE SET item=excluded.item,field=excluded.field,plain=excluded.plain,updated_at=excluded.updated_at`, member, input.project, input.environment, input.variable, action.source?.kind === "item" ? action.source.item : null, input.source.kind === "item" ? input.source.field : null, input.source.kind === "plain" ? input.source.value : null, ctx.now())
        // Source values, fields and private credential identities never enter the chain.
        ctx.audit({ actor: `member:${member}`, action: input.source ? "override.set" : "override.clear", target: input.project, detail: { environment: input.environment, variable: input.variable } })
        return ownOverrides(ctx, member, input.project)
      })
    } },
  },
}

export const resolveOverride: OverrideResolutionHook = (ctx, member, project, environment, variable) => {
  const row = one(ctx.sql.exec<OverrideRow>("SELECT * FROM overrides WHERE member=? AND project=? AND env=? AND name=?", member, project, environment, variable))
  if (!row) return null
  if (row.item === null) return { kind: "plain", value: row.plain! }
  const item = one(ctx.sql.exec<{ slug: string; home_kind: string; home_id: string | null }>("SELECT slug,home_kind,home_id FROM items WHERE id=?", row.item))
  if (!item || item.home_kind !== "member" || item.home_id !== member) missing()
  return { kind: "item", item: item.slug, field: row.field! }
}

// Called inside the protection-change transaction so later loosening cannot revive old choices.
export function clearOverridesForEnvironment(ctx: VaultContext, project: string, environment: string): void {
  ctx.sql.exec("DELETE FROM overrides WHERE project=? AND env=?", project, environment)
}

// Called before the old home changes, in the credential owner's transaction.
export function clearOverridesForCredential(ctx: VaultContext, item: { id: string; home: CredentialHome }, _reason: "deleted" | "rehomed" | "offboarded"): void {
  ctx.sql.exec("DELETE FROM overrides WHERE item=?", item.id)
}
registerOffboardingHook("overrides", (ctx, snapshot) => { ctx.sql.exec("DELETE FROM overrides WHERE member=?", snapshot.member) })
registerAccessChangeHook("overrides", (ctx, member, reason) => {
  if (member && (reason === "suspend" || accessState(ctx).members.find(m => m.id === member)?.status !== "active")) ctx.sql.exec("DELETE FROM overrides WHERE member=?", member)
})
