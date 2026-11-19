import { type CredentialHome, type WorkspaceStepUpAction } from "@mehen/protocol"
import type { AccessPrincipal } from "../src/vault/access.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { accountAuth, accessFixture, inAccess } from "./access-test-support.ts"
import { principalOf, type WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import { credentialAccessState, prepareCredential, registerCredentialServices, storeCredential, type WorkspaceItemInput } from "../src/vault/areas/items-workspace.ts"
export { inAccess }

export async function credentialsFixture() { const f = await accessFixture(); await inAccess(f.tenant, ctx => registerCredentialServices()); return f; }

export function credentialInput(slug: string, home: CredentialHome = { kind: "workspace" }): WorkspaceItemInput { return { slug, home, kind: "api-key", provider: null, account: null, accountVerified: false, tags: [], ceiling: "lease", binding: { hosts: ["api.example.com"] }, policy: { default: "allow", rules: [] }, injection: { in: "header", name: "Authorization", format: "Bearer {key}" }, publicFields: {}, secretFields: { key: "test-secret-never-returned" }, description: null }; }

export function memberInvocation(ctx: VaultContext, role = "owner", action?: WorkspaceStepUpAction): WorkspaceInvocationContext { return { auth: accountAuth(role, action), workspace: { id: ctx.tenant, slug: "work", name: "Work" } }; }

export function memberPrincipal(ctx: VaultContext, role = "owner"): AccessPrincipal { const i = memberInvocation(ctx, role); const p = principalOf(ctx, i.auth); if (p.kind === "system")
  throw new Error("Expected member"); return p; }

export async function seedCredential(ctx: VaultContext, slug: string, home: CredentialHome = { kind: "workspace" }) { const prepared = await prepareCredential(ctx, credentialInput(slug, home), null); return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create")); }

export function devicePrincipal(id = "dev_member"): AccessPrincipal { return { kind: "device", deviceId: id }; }

export function state(ctx: VaultContext) { return credentialAccessState(ctx); }
// Direct-area tests only. Production dispatch verifies the real signature first.

export async function deviceInvocation(ctx: VaultContext, id = "dev_member"): Promise<WorkspaceInvocationContext> {
  const { createProof } = await import("@mehen/protocol")
  const proof = await createProof({ deviceId: id, sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/relay" }, { tenant: ctx.tenant })
  return { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "device", proof, method: "POST", url: "https://vault.test/v1/relay", bodyHash: "" } }
}

// Real workspace connect/start/finish with a local provider; callers replace
// the provider stub when testing refresh races or failures.
export async function seedOAuthConnection(ctx: VaultContext, home: "workspace" | "project" | "private" = "workspace", clientHome: CredentialHome = {kind:"workspace"}) {
  const { getTemplate, WorkspaceStepUpActionSchema } = await import("@mehen/protocol")
  const { createWorkspaceConnect, startWorkspaceConnect, finishWorkspaceConnect, workspaceOAuthOps } = await import("../src/vault/areas/oauth-workspace.ts")
  const { setUpstreamFetch } = await import("../src/relay/upstream.ts")
  const { checkedCredential } = await import("../src/vault/areas/items-workspace.ts")
  const template = getTemplate("google-oauth-client")!
  const client = await prepareCredential(ctx, { ...credentialInput("google-client",clientHome), kind: "oauth-client", provider: template.id, binding: template.binding, policy: template.policy, injection: null, ceiling: "relay", publicFields: { client_id: "test-client" }, secretFields: { client_secret: "test-client-secret" } }, null)
  ctx.storage.transactionSync(() => storeCredential(ctx, client, memberPrincipal(ctx), "item.create"))
  const p = memberPrincipal(ctx), invocation = memberInvocation(ctx)
  const request = createWorkspaceConnect(ctx, p, { provider: "google-gmail", client: "google-client", slug: "gmail-test", home, ...(home === "project" ? { project: "prj_a" } : {}), scopes: ["gmail.modify"] }, invocation)
  const action = WorkspaceStepUpActionSchema.parse(workspaceOAuthOps["oauth.connect_action"].handler(ctx, p, { connect: request.connect }, invocation))
  const state = "fixture-state-123456789"
  await startWorkspaceConnect(ctx, p, { connect: request.connect, state }, memberInvocation(ctx, "owner", action))
  setUpstreamFetch(async request => request.url.includes("/token")
    ? Response.json({ access_token: "test-access", refresh_token: "test-refresh", expires_in: 3600, scope: "openid email https://www.googleapis.com/auth/gmail.modify" })
    : Response.json({ sub: "test-subject", email: "test@example.com", email_verified: true }))
  await finishWorkspaceConnect(ctx, p, { connect: request.connect, state, code: "fixture-code", error: null }, invocation)
  return checkedCredential(ctx, "gmail-test")!
}
