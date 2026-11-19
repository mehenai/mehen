// Every route in PLATFORM_ROUTES probed through the real Worker and real
// managed workspaces: no proof, a malformed or replayed proof, a revoked
// key, a suspended or removed platform, a bad path, query or body, an
// unknown, deleted or purged subject, ids with nothing behind them and the
// platform's own call limit. Each answer is a refusal the reference lists
// for the route (PLATFORM_COMMON_REFUSALS and its own), or a success, never
// a 500, and nothing is logged as an internal error.

import { env } from "cloudflare:workers"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { HTTP_STATUS_FOR_ERROR, PLATFORM_COMMON_REFUSALS, PLATFORM_PROOF_HEADER, PLATFORM_ROUTES, type PlatformRouteName, createPlatformProof } from "@mehen/protocol"
import type { Env } from "../src/env.ts"
import { ORIGIN } from "./helpers.ts"
import { type TestPlatform, addSubject, fetchPlatformRequest, newPlatformKey, platformFetch, registerPlatform } from "./platform-fixtures.ts"

type Route = (typeof PLATFORM_ROUTES)[number]

const SUBJECT = "probe-subject-0001"
const PATH_IDS: Readonly<Record<string, string>> = { device: "dev_probe0001", slug: "probe-item", intake: "int_probe0001", connect: "con_probe0001", approval: "apr_probe0001", project: "prj_probe0001", name: "PROBE_VAR" }

function pathOf(route: Route, subject = SUBJECT): string {
  return route.path.replace(/:([a-z]+)/g, (_, name: string) => (name === "subject" ? subject : (PATH_IDS[name] ?? name)))
}

const sealed = { v: 1, epk: { kty: "EC", crv: "P-256", x: "A".repeat(43), y: "A".repeat(43) }, iv: "A".repeat(16), ct: "AAAA" }

// A body each route's schema takes, naming ids with nothing behind them.
async function sampleBody(name: PlatformRouteName, platform: TestPlatform): Promise<unknown> {
  switch (name) {
    case "devices.create":
      return { name: "Probe agent", jwk: (await newPlatformKey()).jwk, modes: ["relay"] }
    case "intakes.create":
      return { slug: "probe-key", service: { template: "openai" } }
    case "intakes.submit":
      return { sealed: { key: sealed } }
    case "connects.start":
      return { provider: "google-gmail", slug: "probe-gmail", redirectUri: "https://platform.example/callback" }
    case "connects.finish":
      return { state: "s".repeat(32), code: "probe-code" }
    case "approvals.decide":
      return { decision: "approve", digest: "a".repeat(43) }
    case "projects.create":
      return { slug: "probe-project", environments: [{ name: "dev" }], defaultEnv: "dev" }
    case "projects.setVar":
      return { env: "dev", before: null, plain: "hello" }
    case "defaults.put":
      return { scopes: {}, tags: [], customReads: "approve", rules: {} }
    case "subjects.removeAll":
      return { confirm: platform.slug }
    default:
      return {}
  }
}

function hasSubject(route: Route): boolean {
  return route.path.includes(":subject")
}

// What the reference lets the route answer when it refuses.
function allowed(route: Route): string[] {
  return [...PLATFORM_COMMON_REFUSALS, ...route.refusals]
}

type Answer = { status: number; error: string | null; body: Record<string, unknown> }

async function answerOf(response: Response): Promise<Answer> {
  const text = await response.text()
  const body = text === "" ? {} : (JSON.parse(text) as Record<string, unknown>)
  return { status: response.status, error: typeof body.error === "string" ? body.error : null, body }
}

// A refusal the route documents, with its documented status, and never a
// link or a command for the platform.
function expectDocumented(route: Route, probe: string, answer: Answer, code?: string): void {
  const where = `${route.name}: ${probe}`
  expect(answer.status, where).toBeLessThan(500)
  if (answer.status < 400) {
    expect(code, `${where} answered ${answer.status}`).toBeUndefined()
    return
  }
  expect(answer.error, where).not.toBeNull()
  if (code !== undefined) expect(answer.error, where).toBe(code)
  expect(allowed(route), `${where} answered ${answer.error}`).toContain(answer.error)
  // A wrong method's 405 is the one status that is not the code's own.
  if (answer.status !== 405) expect(answer.status, where).toBe(HTTP_STATUS_FOR_ERROR[answer.error as keyof typeof HTTP_STATUS_FOR_ERROR])
  const next = answer.body.next as Record<string, unknown> | undefined
  expect(next?.url, where).toBeUndefined()
  expect(next?.command, where).toBeUndefined()
  // Nor a sentence telling it to run the CLI.
  expect(String(next?.say ?? ""), where).not.toMatch(/`mehen\b/)
}

// A platform with a live subject in a real managed workspace.
async function platformWithSubject(world: Env, options: Parameters<typeof registerPlatform>[1] = {}): Promise<TestPlatform> {
  const platform = await registerPlatform(world, options)
  const made = await platformFetch(world, platform, { method: "PUT", path: `/v1/platform/subjects/${SUBJECT}`, body: {} })
  expect(made.status).toBe(201)
  return platform
}

async function call(world: Env, platform: TestPlatform, route: Route, options: { subject?: string; body?: unknown; query?: string } = {}): Promise<Answer> {
  const path = `${pathOf(route, options.subject)}${options.query ?? ""}`
  const body = route.body === null ? undefined : (options.body ?? (await sampleBody(route.name, platform)))
  return answerOf(await platformFetch(world, platform, { method: route.method, path, ...(body !== undefined ? { body } : {}) }))
}

// A body sent as these exact bytes, the proof signed over them.
async function rawCall(world: Env, platform: TestPlatform, route: Route, text: string): Promise<Answer> {
  const url = `${ORIGIN}${pathOf(route)}`
  const proof = await createPlatformProof(platform.signer, { method: route.method, url, body: text })
  return answerOf(await fetchPlatformRequest(world, new Request(url, { method: route.method, headers: { "content-type": "application/json", [PLATFORM_PROOF_HEADER]: proof }, body: text })))
}

let errors: ReturnType<typeof vi.spyOn>

beforeEach(() => {
  errors = vi.spyOn(console, "error")
})

afterEach(() => {
  expect(errors).not.toHaveBeenCalled()
  errors.mockRestore()
})

describe.each(PLATFORM_ROUTES.map((route) => [route.name, route] as const))("%s", (_, route) => {
  it("refuses a call with no proof, a malformed one, a replayed one and a revoked key's", async () => {
    const world = env as Env
    const platform = await platformWithSubject(world)
    const url = `${ORIGIN}${pathOf(route)}`
    const body = route.body === null ? null : JSON.stringify(await sampleBody(route.name, platform))
    const headers: Record<string, string> = body === null ? {} : { "content-type": "application/json" }
    const send = (proof: string | null) => fetchPlatformRequest(world, new Request(url, { method: route.method, headers: { ...headers, ...(proof !== null ? { [PLATFORM_PROOF_HEADER]: proof } : {}) }, ...(body !== null ? { body } : {}) }))
    expectDocumented(route, "no proof", await answerOf(await send(null)), "unauthenticated")
    expectDocumented(route, "a malformed proof", await answerOf(await send("not-a-proof")), "proof_invalid")
    const proof = await createPlatformProof(platform.signer, { method: route.method, url, body })
    expectDocumented(route, "the first use of a proof", await answerOf(await send(proof)))
    expectDocumented(route, "the proof replayed", await answerOf(await send(proof)), "proof_invalid")
    await world.DB.prepare("UPDATE platform_keys SET revoked_at=? WHERE id=?").bind(Date.now(), platform.key).run()
    expectDocumented(route, "a revoked key", await call(world, platform, route), "unauthenticated")
  })

  it("refuses a bad path, a query it does not take and a body it does not take", async () => {
    const world = env as Env
    const platform = await platformWithSubject(world)
    // A segment that is no subject never equals the proof's `sub`, which
    // the signer takes only from a valid one: the proof is refused first.
    if (hasSubject(route)) expectDocumented(route, "a malformed subject", await call(world, platform, route, { subject: "x" }), "proof_invalid")
    expectDocumented(route, "an unknown query parameter", await call(world, platform, route, { query: "?probe=1" }), "bad_request")
    // A GET cannot carry a body at all.
    if (route.body === null && route.method !== "GET") {
      const answer = await answerOf(await platformFetch(world, platform, { method: route.method, path: pathOf(route), body: {} }))
      expectDocumented(route, "a body on a route with none", answer, "bad_request")
    } else if (route.body !== null) {
      expectDocumented(route, "a member the body does not take", await call(world, platform, route, { body: { probe: true } }), "bad_request")
      expectDocumented(route, "a body that is not JSON", await rawCall(world, platform, route, "{not json"), "bad_request")
    }
  })

  it("answers the documented refusal for ids with nothing behind them, and for an unknown, deleted or purged subject", async () => {
    const world = env as Env
    const platform = await platformWithSubject(world)
    await addSubject(world, platform.id, "probe-subject-purged", "purged")
    expectDocumented(route, "a live subject", await call(world, platform, route))
    if (!hasSubject(route) || route.name === "subjects.ensure") return
    expectDocumented(route, "an unknown subject", await call(world, platform, route, { subject: "probe-subject-none" }), "not_found")
    expectDocumented(route, "a purged subject", await call(world, platform, route, { subject: "probe-subject-purged" }), "not_found")
    const other = await platformWithSubject(world)
    const removed = await platformFetch(world, other, { method: "DELETE", path: `/v1/platform/subjects/${SUBJECT}`, body: {} })
    expect(removed.status).toBe(200)
    // A deleted subject is read, and deleted again, until its purge; its
    // audit stays readable; everything else is not found.
    const readable = ["subjects.get", "subjects.remove", "audit.read"].includes(route.name)
    expectDocumented(route, "a deleted subject", await call(world, other, route), readable ? undefined : "not_found")
  })

  it("refuses every call of a suspended platform and of one being removed", async () => {
    const world = env as Env
    const suspended = await platformWithSubject(world)
    await world.DB.prepare("UPDATE platforms SET status='suspended' WHERE id=?").bind(suspended.id).run()
    expectDocumented(route, "a suspended platform", await call(world, suspended, route), "platform_suspended")
    const removing = await platformWithSubject(world)
    const now = Date.now()
    await world.DB.prepare("UPDATE platforms SET status='retiring',retire_after=?,removing_at=?,removing_by='operator:probe' WHERE id=?").bind(now, now, removing.id).run()
    expectDocumented(route, "a platform being removed", await call(world, removing, route), "platform_suspended")
  })

  it("refuses a call past the platform's calls a minute, with when to retry", async () => {
    const world = env as Env
    const platform = await platformWithSubject(world, { limits: { callsPerMinute: 1 } })
    // The window is a fixed minute, so it can turn between any two calls;
    // it turns at most once in a few seconds, so of three calls in a row
    // the second or the third is past the limit. When it turns after the
    // first, the second is admitted and may still fail on its own (a removed
    // project is not_found), so only rate_limited ends the retry.
    expectDocumented(route, "at the limit", await call(world, platform, route))
    let answer = await call(world, platform, route)
    if (answer.error !== "rate_limited") answer = await call(world, platform, route)
    expectDocumented(route, "past calls a minute", answer, "rate_limited")
    expect(answer.body.retryAfter).toEqual(expect.any(Number))
  })
})
