// Holds or replaces a workspace's pending.inbox call after the Worker has made
// its D1 reads (session, memberships, candidates, session check), so a test
// can change the workspace in between or make it fail. Returns the restore.
import type { InvocationResult, WorkspaceInvocation } from "../../src/vault/core.ts"
import type { Env } from "../../src/env.ts"

type InboxCall = (workspace: string, invocation: WorkspaceInvocation, proceed: () => Promise<InvocationResult>) => Promise<InvocationResult>
export function interceptInbox(f: { env: Env }, call: InboxCall): () => void {
  const original = f.env.TENANT_VAULT
  f.env.TENANT_VAULT = new Proxy(original, { get(target, key) {
    if (key === "getByName") return (name: string) => {
      const stub = target.getByName(name)
      return new Proxy(stub, { get(object, prop) {
        if (prop === "invoke") return (invocation: WorkspaceInvocation) => invocation.op === "pending.inbox" ? call(name, invocation, () => object.invoke(invocation)) : object.invoke(invocation)
        const value = Reflect.get(object, prop) as unknown
        return typeof value === "function" ? value.bind(object) : value
      } })
    }
    const value = Reflect.get(target, key) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  return () => { f.env.TENANT_VAULT = original }
}
