// Raw resource state for shared relay-engine tests, not legacy RPC handlers.
import { randomId } from "@mehen/protocol"
import type { VaultContext } from "../src/vault/core.ts"
import type { SetEnvironmentInput, SetVarInput } from "../src/vault/areas/projects.ts"

export function seedRelayProject(ctx: VaultContext,input: { slug: string; remote: string | null; defaultEnv: string; environments: { name: string; protected: boolean }[] }): string {
  const id = randomId("prj")
  ctx.sql.exec("INSERT INTO projects(id,slug,default_env,created_by,created_at,updated_at) VALUES (?,?,?,'system',?,?)",id,input.slug,input.defaultEnv,ctx.now(),ctx.now())
  for (const env of input.environments) ctx.sql.exec("INSERT INTO environments(project,name,protected,fences) VALUES (?,?,?,'[]')",id,env.name,Number(env.protected))
  if (input.remote) ctx.sql.exec("INSERT INTO remotes(remote,project) VALUES (?,?)",input.remote,id)
  return id
}
export function seedRelayVar(ctx: VaultContext,input: SetVarInput): void {
  ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,plain,updated_by,updated_at) VALUES (?,?,?,?,?,?,'system',?) ON CONFLICT(project,env,name) DO UPDATE SET item=excluded.item,field=excluded.field,plain=excluded.plain",input.project,input.env,input.name,input.item ?? null,input.field ?? "key",input.plain ?? null,ctx.now())
}
export function seedRelayEnvironment(ctx: VaultContext,input: SetEnvironmentInput): void {
  ctx.sql.exec("UPDATE environments SET protected=?,fences=? WHERE project=? AND name=?",Number(input.protected),JSON.stringify(input.fences),input.project,input.env)
}
