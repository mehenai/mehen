// One page request's directory reads (routes/ui.ts workspacePagePrefix). A
// GET or HEAD page and the reads it dispatches inside the Worker share one
// answer to each session lookup, workspace resolve and session identity
// check, instead of asking D1 again for each read. One top-level request is
// one authorisation decision, and the workspace object still checks epoch
// and revocation on every call. Nothing outlives the request; a request that
// is not a GET or HEAD neither reads nor fills it; a read that fails is
// forgotten, so the next asks D1 again.
import { AsyncLocalStorage } from "node:async_hooks"

const current = new AsyncLocalStorage<Map<string, Promise<unknown>>>()

function reads(request: Request): boolean {
  return request.method === "GET" || request.method === "HEAD"
}

export function withPageReads<T>(request: Request, work: () => Promise<T>): Promise<T> {
  return reads(request) ? current.run(new Map(), work) : work()
}

export function pageRead<T>(request: Request, key: string, read: () => Promise<T>): Promise<T> {
  const memo = reads(request) ? current.getStore() : undefined
  if (!memo) return read()
  const known = memo.get(key) as Promise<T> | undefined
  if (known) return known
  const answer = read()
  memo.set(key, answer)
  answer.catch(() => { if (memo.get(key) === answer) memo.delete(key) })
  return answer
}
