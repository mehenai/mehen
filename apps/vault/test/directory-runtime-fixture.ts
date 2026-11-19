import { createExecutionContext } from "cloudflare:test"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { accessFixture,registerFixtureLifecycleHooks } from "./access-test-support.ts"
import { insertAccountPasskey } from "../src/directory/account-store.ts"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { startAccountStepUp } from "../src/directory/workspace-stepup.ts"
import { resolveWorkspace,type RequestContext } from "../src/routes/context.ts"
export async function directoryRuntimeFixture() {
  registerFixtureLifecycleHooks()
  const f = await createWorkspaceFixture(),live = await accessFixture(),now = Date.now()
  await f.env.DB.batch([
    f.env.DB.prepare("DELETE FROM memberships WHERE workspace=?").bind(f.workspaces.work),
    f.env.DB.prepare("DELETE FROM workspaces WHERE id=?").bind(f.workspaces.work),
    f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at) VALUES (?,'work','Work','active',?,?)").bind(live.tenant,f.account,now),
    ...live.state.members.map(m => f.env.DB.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES (?,?,?,'member',?,?)").bind(m.id,m.account,live.tenant,m.standing.effectiveRole,now)),
  ])
  f.workspaces.work = live.tenant
  await insertAccountPasskey(f.env,f.account,{ credentialId: "credential",publicKey: new Uint8Array([1]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null },now-1000,"signup","pk_test").run()
  const context = (path: string,body?: unknown,params: Record<string,string> = {}): RequestContext => {
    const url = new URL(`${f.env.VAULT_ORIGIN}/api/w/work${path}`)
    return { request: new Request(url,{ method: body === undefined ? "GET" : "POST",headers: { cookie: f.cookie,origin: f.env.VAULT_ORIGIN,"content-type": "application/json" },...(body === undefined ? {} : { body: JSON.stringify(body) }) }),env: f.env,ctx: createExecutionContext(),url,params: { ws: "work",...params } }
  }
  const workspace = await resolveWorkspace(context(""))
  const proof = async (action: WorkspaceStepUpAction) => {
    const account = await currentAccountSession(context("").request,f.env)
    if (!account) throw new Error("Missing account")
    return { nonce: (await startAccountStepUp(f.env,account,live.tenant,action)).nonce,assertion: { id: "credential",rawId: "credential",type: "public-key",response: {} } }
  }
  return { ...f,tenant: live.tenant,context,workspace,proof }
}
