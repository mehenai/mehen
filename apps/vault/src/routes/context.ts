// What every route handler receives, and the two ways into a tenant vault:
// as a device (the Worker forwards the Mehen-Proof, the DO verifies it) or as
// a signed-in member (the Worker has checked the session cookie).

import { bodyHash, parseProof } from "@mehen/protocol"
import { cliVersionOf } from "../cli-version.ts"
import type { Env } from "../env.ts"
import { VaultError, readBody } from "../http.ts"
import { pageRead } from "../page-reads.ts"
import { timed } from "../server-timing.ts"
import type { Params } from "../router.ts"
import { invokeVault } from "../vault/client.ts"

export type RequestContext = {
  request: Request
  env: Env
  ctx: ExecutionContext
  url: URL
  params: Params
}

export type Handler = (rc: RequestContext) => Promise<Response>

export const PROOF_HEADER = "Mehen-Proof"

export type DeviceRequest = { tenant: string; body: Uint8Array<ArrayBuffer>; call(op: string, input?: unknown): Promise<unknown> }

// Reads the body once, hashes it for the proof, and returns a caller bound
// to this request's proof. The tenant comes from the unverified proof only
// to route; the DO refuses unless the device's key verifies it.
export async function deviceRequest(rc: RequestContext, limit?: number): Promise<DeviceRequest> {
  const proof = rc.request.headers.get(PROOF_HEADER)
  if (!proof) {
    throw new VaultError("unauthenticated", "Missing Mehen-Proof. Use the mehen CLI, which signs every request with this machine's device key.", {
      next: { command: "mehen enrol --workspace <slug>", say: "This machine is not enrolled with the vault yet; run `mehen enrol --workspace <slug>` with the slug from the workspace's Connect an agent page and approve it in the browser." },
    })
  }
  let tenant: string
  try {
    tenant = parseProof(proof).claims.ten
  } catch {
    throw new VaultError("proof_invalid", "The Mehen-Proof header is malformed.")
  }
  // A key that is still enrolling signs as tenant "enrol" (directory/enrolment.ts).
  if (tenant === "enrol") {
    throw new VaultError("device_pending", "This machine's enrolment has not been approved yet.", {
      next: { say: "Open the link `mehen enrol` printed, sign in with your passkey and approve this machine, then retry." },
    })
  }
  const body = await readBody(rc.request, limit)
  const hash = await bodyHash(body)
  const cliVersion = cliVersionOf(rc.request.headers.get("user-agent"))
  return {
    tenant,
    body,
    call: (op, input) =>
      invokeVault(rc.env, tenant, { op, input, auth: { kind: "device", proof, method: rc.request.method, url: rc.request.url, bodyHash: hash, cliVersion } }),
  }
}

export type WorkspaceRequest = { workspace: import("@mehen/protocol").WorkspaceRef; membership: string; account: import("../directory/account-session.ts").AccountWebSession; sessionKind?: "web" | "app" }
export async function resolveWorkspace(rc: RequestContext): Promise<WorkspaceRequest> {
  const { currentAccountSession } = await import("../directory/account-session.ts")
  const account = await currentAccountSession(rc.request, rc.env)
  if (!account) throw new VaultError("unauthenticated", "Sign in with your passkey to continue.")
  if (account.transition) {
    const { retryAccountSecurityIfDue } = await import("../directory/account-security.ts")
    rc.ctx.waitUntil(retryAccountSecurityIfDue(rc.env, account.transition).catch(() => console.error(JSON.stringify({ at: "account.security.retry", transition: account.transition }))))
  }
  const ws = rc.params.ws
  const row = await pageRead(rc.request, `workspace:${account.account}:${ws}`, () => rc.env.DB.prepare(`SELECT w.id,w.slug,w.name,m.id AS membership FROM workspaces w JOIN memberships m ON m.workspace=w.id AND m.account=? AND m.state='member' WHERE w.status='active' AND (w.slug=? OR EXISTS (SELECT 1 FROM workspace_slugs s WHERE s.workspace=w.id AND s.slug=?))`).bind(account.account, ws, ws).first<{ id: string; slug: string; name: string; membership: string }>())
  if (!row) throw new VaultError("not_found", "No such workspace.")
  return { workspace: { id: row.id, slug: row.slug, name: row.name }, membership: row.membership, account }
}
export async function workspaceCall(rc: RequestContext, workspace: WorkspaceRequest, op: string, input?: unknown, evidence?: { action: import("@mehen/protocol").WorkspaceStepUpAction; factor: string; confirmation?: import("@mehen/protocol").StepUpConfirmation; operationCheck?: import("../vault/core.ts").OperationCheck }, injectedStub?: import("../vault/core.ts").WorkspaceVaultStub): Promise<unknown> {
  const { TENANT_ID } = await import("../vault/client.ts")
  if (!TENANT_ID.test(workspace.workspace.id)) throw new VaultError("not_found", "No such workspace.")
  const kind = workspace.sessionKind ?? "web"
  const sessionCheck = await pageRead(rc.request, `check:${workspace.account.session}:${workspace.workspace.id}:${kind}:${workspace.account.securityEpoch}:${workspace.membership}`, () => rc.env.DB.prepare("SELECT id,rule_revision AS identityRuleRev,gate_generation AS gateGeneration,sequence AS checkSequence,succeeded_at,expires_at FROM session_identity_checks WHERE session=? AND workspace=? AND session_kind=? AND security_epoch=? AND member=? AND expires_at>?").bind(workspace.account.session, workspace.workspace.id, kind, workspace.account.securityEpoch, workspace.membership, Date.now()).first<{ id: string; identityRuleRev: number; gateGeneration: number; checkSequence: number; succeeded_at: number; expires_at: number }>())
  const stub = injectedStub ?? rc.env.TENANT_VAULT.getByName(workspace.workspace.id)
  const result = await timed("workspace", () => stub.invoke({ op, input, auth: { kind: "account", account: workspace.account.account, session: workspace.account.session, securityEpoch: workspace.account.securityEpoch, restrictedUntil: workspace.account.restrictedUntil, sessionCheck: sessionCheck ? { id: sessionCheck.id, identityRuleRev: sessionCheck.identityRuleRev, gateGeneration: sessionCheck.gateGeneration, checkSequence: sessionCheck.checkSequence, succeededAt: new Date(sessionCheck.succeeded_at).toISOString(), expiresAt: new Date(sessionCheck.expires_at).toISOString() } : null, ...(evidence ? { stepUp: evidence.action, stepUpFactor: evidence.factor, ...(evidence.confirmation ? { stepUpConfirmation: evidence.confirmation } : {}), ...(evidence.operationCheck ? { operationCheck: evidence.operationCheck } : {}) } : {}) } }))
  if (result.ok) return result.value
  const { error, message, ...extra } = result.error.vaultError
  throw new VaultError(error, message, extra)
}
