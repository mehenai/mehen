// The directory's two system calls into a workspace object for the
// operator console (access.operator_view and access.operator_freeze in
// vault/areas/access.ts), refused to every other caller.

import type { z } from "zod"
import type { Env } from "../env.ts"
import { invokeVault } from "../vault/client.ts"
import { OperatorFreezeAnswerSchema, OperatorWorkspaceViewSchema } from "../vault/areas/access.ts"

export type OperatorWorkspaceView = z.infer<typeof OperatorWorkspaceViewSchema>
export type OperatorWorkspaceClient = {
  view(tenant: string): Promise<OperatorWorkspaceView>
  // The workspace's own freeze, as `operator`; the owners and admins to tell.
  freeze(tenant: string, operator: string): Promise<{ already: boolean; notify: string[] }>
}

export function operatorWorkspaceClient(env: Env): OperatorWorkspaceClient {
  const system = (tenant: string, op: string, input: unknown) => invokeVault(env, tenant, { op, input, auth: { kind: "system", reason: "operator console" } })
  return {
    view: async (tenant) => OperatorWorkspaceViewSchema.parse(await system(tenant, "access.operator_view", {})),
    freeze: async (tenant, operator) => {
      const answer = OperatorFreezeAnswerSchema.parse(await system(tenant, "access.operator_freeze", { operator }))
      return { already: answer.already, notify: answer.notify }
    },
  }
}
