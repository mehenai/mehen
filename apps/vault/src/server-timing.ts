// Server-Timing on the web pages and GET /api/needs-you: how long one
// request spent in each phase, under fixed names and nothing else, so the
// browser shows what a page cost. A phase is the wall time during which at
// least one piece of its work was open, so calls in parallel count once.
// The agents' /v1 routes, the health check, the OAuth and Google sign-in
// callbacks, redirects and anything else that is not an HTML page never
// carry it.
import { AsyncLocalStorage } from "node:async_hooks"
import type { Env } from "./env.ts"

export const TIMING_PHASES = ["session", "d1", "inbox", "workspace", "render", "total"] as const
export type TimingPhase = (typeof TIMING_PHASES)[number]

class RequestTiming {
  private readonly open = new Map<TimingPhase, { count: number; since: number }>()
  private readonly spent = new Map<TimingPhase, number>()
  constructor(private readonly clock: () => number) {}
  enter(phase: TimingPhase): void {
    const open = this.open.get(phase)
    if (open) open.count++
    else this.open.set(phase, { count: 1, since: this.clock() })
  }
  leave(phase: TimingPhase): void {
    const open = this.open.get(phase)
    if (!open || --open.count > 0) return
    this.open.delete(phase)
    this.spent.set(phase, (this.spent.get(phase) ?? 0) + this.clock() - open.since)
  }
  header(): string {
    return TIMING_PHASES.filter((phase) => this.spent.has(phase)).map((phase) => `${phase};dur=${Math.round(this.spent.get(phase)! * 10) / 10}`).join(", ")
  }
}

const current = new AsyncLocalStorage<RequestTiming>()

const NEEDS_YOU = "/api/needs-you"

// The web pages and the account-wide inbox; not the API, the agents' /v1,
// a native app's /app/v1, the assets, the health check or the OAuth and
// Google sign-in callbacks. A platform's own API is excluded where this is
// called (index.ts).
export function timesRequest(request: Request, url: URL): boolean {
  if (request.method !== "GET" && request.method !== "HEAD") return false
  if (url.pathname === NEEDS_YOU) return true
  if (url.pathname === "/healthz") return false
  return !["/api/", "/v1/", "/app/", "/assets/", "/oauth/", "/auth/oidc/"].some((prefix) => url.pathname.startsWith(prefix))
}

// Of what a timed request answers, only an HTML page and the inbox, 304
// included, carry the header: not a redirect, a download or JSON.
export function carriesServerTiming(url: URL, response: Response): boolean {
  return url.pathname === NEEDS_YOU || (response.headers.get("content-type") ?? "").startsWith("text/html")
}

// Runs one request with its timing, and adds the header to what it answers
// when `carries` lets it.
export async function withServerTiming(handle: () => Promise<Response>, carries: (response: Response) => boolean = () => true, clock: () => number = () => performance.now()): Promise<Response> {
  const timing = new RequestTiming(clock)
  const answered = await current.run(timing, () => timed("total", handle))
  if (!carries(answered)) return answered
  const response = new Response(answered.body, answered)
  response.headers.set("server-timing", timing.header())
  return response
}

export async function timed<T>(phase: TimingPhase, work: () => Promise<T>): Promise<T> {
  const timing = current.getStore()
  if (!timing) return work()
  timing.enter(phase)
  try {
    return await work()
  } finally {
    timing.leave(phase)
  }
}

export function timedSync<T>(phase: TimingPhase, work: () => T): T {
  const timing = current.getStore()
  if (!timing) return work()
  timing.enter(phase)
  try {
    return work()
  } finally {
    timing.leave(phase)
  }
}

// The same env, read live, with every D1 round trip timed as d1. One timed
// D1 per binding, so what is cached against the binding's identity
// (workspace-cutover.ts) stays cached from request to request.
export function timedEnv(env: Env): Env {
  return new Proxy(env, { get(target, key) {
    return key === "DB" ? timedD1(target.DB) : Reflect.get(target, key, target) as unknown
  } })
}

const timedD1s = new WeakMap<D1Database, D1Database>()
function timedD1(db: D1Database): D1Database {
  let timed = timedD1s.get(db)
  if (!timed) {
    timed = timingD1(db)
    timedD1s.set(db, timed)
  }
  return timed
}

function timingD1(db: D1Database): D1Database {
  const real = new WeakMap<object, D1PreparedStatement>()
  const statement = (prepared: D1PreparedStatement): D1PreparedStatement => {
    const proxy = new Proxy(prepared, { get(target, key) {
      if (key === "bind") return (...values: unknown[]) => statement(target.bind(...values))
      const value = Reflect.get(target, key, target) as unknown
      if (typeof value !== "function") return value
      if (key === "first" || key === "all" || key === "run" || key === "raw") return (...args: unknown[]) => timed("d1", async () => (value as (...a: unknown[]) => Promise<unknown>).apply(target, args))
      return (value as (...a: unknown[]) => unknown).bind(target)
    } })
    real.set(proxy, prepared)
    return proxy
  }
  return new Proxy(db, { get(target, key) {
    if (key === "prepare") return (query: string) => statement(target.prepare(query))
    if (key === "batch") return (statements: D1PreparedStatement[]) => timed("d1", () => target.batch(statements.map((s) => real.get(s) ?? s)))
    if (key === "exec") return (query: string) => timed("d1", () => target.exec(query))
    const value = Reflect.get(target, key, target) as unknown
    return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value
  } })
}
