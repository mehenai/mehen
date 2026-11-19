import { exhaustedNameBudget } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { assertWorkspaceNameAvailable,type WorkspaceSlugRows } from "../routes/workspace-prefix.ts"
export async function assertWorkspaceNameBudget(env: Env,account: string,now = Date.now()): Promise<void> {
  const window = now-now%3600000
  const row = await env.DB.prepare("SELECT count FROM auth_attempts WHERE key=? AND window_start=?").bind(`workspace-name:${account}`,window).first<{ count: number }>()
  const refusal = exhaustedNameBudget([{ windowStart: window,count: row?.count ?? 0 }],now)
  if (refusal) throw new VaultError(refusal.error,refusal.message,{ retryAfter: refusal.retryAfter })
}
export async function checkWorkspaceName(env: Env,account: string,slug: string,rows: WorkspaceSlugRows,renamingWorkspace?: string,now = Date.now()): Promise<void> {
  await assertWorkspaceNameBudget(env,account,now)
  try { assertWorkspaceNameAvailable(slug,rows,renamingWorkspace) } catch (error) {
    if (!(error instanceof VaultError) || error.code !== "conflict") throw error
    const key = `workspace-name:${account}`,window = now-now%3600000
    await env.DB.batch([
      env.DB.prepare("INSERT INTO auth_attempts(key,window_start,count) VALUES (?,?,1) ON CONFLICT(key,window_start) DO UPDATE SET count=MIN(count+1,20)").bind(key,window),
      env.DB.prepare("INSERT OR IGNORE INTO account_events(id,account,at,action,detail) SELECT ?,?,?,'account.workspace_name_limit',? WHERE EXISTS (SELECT 1 FROM auth_attempts WHERE key=? AND window_start=? AND count=20)")
        .bind(`name-limit:${account}:${window}`,account,now,JSON.stringify({ count: 20 }),key,window),
    ])
    throw error
  }
}
