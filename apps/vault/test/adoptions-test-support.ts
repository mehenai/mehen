// Calls into the adoptions area for its tests: a machine starts and fills a
// batch with sealed rows, a person views and approves it.
import { adoptionDigest, adoptionRepoints, adoptionSealContext, importSealPublicKey, seal, type CredentialHome, type AdoptionCreated, type AdoptionDecisionInput, type AdoptionIndexed, type AdoptionIndexInput, type WorkspaceAdoptionInventory, type AdoptionItemUploadInput, type AdoptionStatus, type AdoptionUploaded, type WorkspaceAdoptionView } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { sealPublicJwk } from "../src/seal-key.ts"
import type { AccessState } from "../src/vault/access.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { prepareCredential, storeCredential } from "../src/vault/areas/items-workspace.ts"
import { workspaceAdoptionOps } from "../src/vault/areas/adoptions.ts"
import type { WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import { credentialInput, deviceInvocation, devicePrincipal, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"

export const SENTINEL = "sk-proj-adopt-sentinel-0123456789abcdefghij"

export type AdoptionOp = keyof typeof workspaceAdoptionOps
export async function call<T>(ctx: VaultContext, op: AdoptionOp, input: unknown, invocation: WorkspaceInvocationContext, p = invocation.auth.kind === "device" ? devicePrincipal(deviceOf(invocation)) : memberPrincipal(ctx, roleOf(invocation))): Promise<T> {
  return await workspaceAdoptionOps[op].handler(ctx, p, input, invocation) as T
}
function deviceOf(invocation: WorkspaceInvocationContext): string { return JSON.parse(atob((invocation.auth as { proof: string }).proof.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))).dev }
function roleOf(invocation: WorkspaceInvocationContext): string { return (invocation.auth as { account: string }).account.slice(4) }
export async function refused(promise: Promise<unknown> | (() => unknown)): Promise<{ error: string; message: string; refused?: unknown }> {
  try { await (typeof promise === "function" ? promise() : promise) } catch (error) { if (error instanceof VaultError) return error.toJSON() as { error: string; message: string }; throw error }
  throw new Error("accepted")
}

export async function box(ctx: VaultContext, adoption: string, ref: string, field: string, value: string) {
  const { jwk } = await sealPublicJwk(ctx.env)
  return seal(await importSealPublicKey(jwk), value, adoptionSealContext(adoption, ref, field))
}
export async function item(ctx: VaultContext, adoption: string, ref: string, slug: string, value = SENTINEL, extra: Partial<AdoptionItemUploadInput> = {}): Promise<AdoptionItemUploadInput> {
  return { ref, slug, kind: "api-key", provider: "openai", binding: null, injection: null, home: { kind: "workspace" }, tags: ["adopted"], publicFields: {}, sealed: { key: await box(ctx, adoption, ref, "key", value) }, sources: [{ path: "/home/alex/app/.env", variable: "OPENAI_API_KEY", stale: [] }], repo: { remote: "github.com/alex/app", env: "dev" }, ...extra }
}
export async function start(ctx: VaultContext, device = "dev_owner"): Promise<AdoptionCreated> {
  return call<AdoptionCreated>(ctx, "adoption.create", { machine: "office", expectedItems: 2 }, await deviceInvocation(ctx, device))
}
export async function upload(ctx: VaultContext, adoption: string, items: AdoptionItemUploadInput[], device = "dev_owner"): Promise<AdoptionUploaded> {
  return call<AdoptionUploaded>(ctx, "adoption.upload", { adoption, items }, await deviceInvocation(ctx, device))
}
export async function status(ctx: VaultContext, adoption: string, device = "dev_owner"): Promise<AdoptionStatus> {
  return call<AdoptionStatus>(ctx, "adoption.status", { adoption }, await deviceInvocation(ctx, device))
}
export function view(ctx: VaultContext, adoption: string, role = "owner"): Promise<WorkspaceAdoptionView> {
  return call<WorkspaceAdoptionView>(ctx, "adoption.view", { adoption }, memberInvocation(ctx, role))
}
export async function approve(ctx: VaultContext, v: WorkspaceAdoptionView, decisions: AdoptionDecisionInput[], role = "owner", digest?: string): Promise<AdoptionStatus> {
  const action = { type: "adoption.approve" as const, adoption: v.adoption, digest: digest ?? await adoptionDigest(v.adoption, v.items, decisions), repoints: adoptionRepoints(decisions) }
  return call<AdoptionStatus>(ctx, "adoption.approve", { adoption: v.adoption, decisions }, memberInvocation(ctx, role, action))
}
export function storedFingerprint(ctx: VaultContext, item: string, field = "key"): string | undefined {
  return ctx.sql.exec<{ fingerprint: string }>("SELECT fingerprint FROM item_secrets WHERE item=? AND name=?", item, field).toArray()[0]?.fingerprint
}
// Another machine of the owner, for `mehen adopt submit --join`.
export function secondMachine(ctx: VaultContext, id = "dev_owner2", name = "laptop"): string {
  ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) SELECT ?,?,backend,jwk,?,scope,created_at,owner_kind,owner_id FROM devices WHERE id='dev_owner'", id, name, id)
  return id
}
export function matches(ctx: VaultContext, adoption: string): Record<string, { holder: string | null; version: number | null; match: (string | null)[] }> {
  const items = ctx.sql.exec<{ ref: string; holder: string | null; holder_version: number | null }>("SELECT ref,holder,holder_version FROM adoption_items WHERE adoption=? AND status='staged' ORDER BY ref", adoption).toArray()
  return Object.fromEntries(items.map(i => [i.ref, { holder: i.holder, version: i.holder_version, match: ctx.sql.exec<{ match: string | null }>("SELECT match FROM adoption_secrets WHERE adoption=? AND ref=? ORDER BY field", adoption, i.ref).toArray().map(s => s.match) }]))
}
// Points a project variable at an item in the seeded access state.
export function addReference(ctx: VaultContext, item: { id: string; home: CredentialHome }, project: string, env: string, variable = "TOKEN"): void {
  const state = JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM access_fixture_state").one().value) as AccessState
  state.projects.find(p => p.id === project)!.environments.find(e => e.name === env)!.references.push({ variable, field: "key", item: item.id, home: item.home, revision: 1 })
  ctx.sql.exec("UPDATE access_fixture_state SET value=?", JSON.stringify(state))
}
// A generic credential, a low-entropy kind, holding `value`.
export async function seedGeneric(ctx: VaultContext, slug: string, value: string, home: CredentialHome = { kind: "workspace" }) {
  const prepared = await prepareCredential(ctx, { ...credentialInput(slug, home), kind: "generic", injection: null, secretFields: { value } }, null)
  return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
}
export async function genericItem(ctx: VaultContext, adoption: string, ref: string, slug: string, value: string, extra: Partial<AdoptionItemUploadInput> = {}): Promise<AdoptionItemUploadInput> {
  return item(ctx, adoption, ref, slug, value, { kind: "generic", provider: null, binding: { hosts: ["api.example.com"] }, sealed: { value: await box(ctx, adoption, ref, "value", value) }, ...extra })
}
// A machine accepted with private credentials, so it may adopt into its owner's home.
export function allowPrivate(ctx: VaultContext, device: string): void {
  ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id=?", device)
}
export function planItem(ref: string, slug: string, extra: Partial<AdoptionIndexInput["items"][number]> = {}): AdoptionIndexInput["items"][number] {
  return { ref, slug, kind: "api-key", provider: "openai", home: "workspace", project: null, include: true, exists: false, storeOnly: false, sources: [{ path: "/home/alex/app/.env", variable: "OPENAI_API_KEY", stale: [], mtime: "2026-11-01T10:00:00.000Z" }], uses: [{ project: "prj_a", env: "dev", variable: "OPENAI_API_KEY", field: "key" }], ...extra }
}
export async function sendIndex(ctx: VaultContext, items: AdoptionIndexInput["items"], device = "dev_owner", machine = "office"): Promise<AdoptionIndexed> {
  return call<AdoptionIndexed>(ctx, "adoption.index", { machine, items }, await deviceInvocation(ctx, device))
}
export function inventory(ctx: VaultContext, role = "owner"): Promise<WorkspaceAdoptionInventory> {
  return call<WorkspaceAdoptionInventory>(ctx, "adoption.inventory", {}, memberInvocation(ctx, role))
}
