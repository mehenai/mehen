// Bad input through the real Worker and Durable Object. Every /v1 device
// route and every /api/w workspace route is probed with malformed,
// mistyped, oversized and foreign input, and from a revoked machine, an
// ended workload, a removed member's machine and a frozen workspace. None
// may answer a 500: each refusal is the vault's JSON, with Mehen-Error, a
// code from ERROR_CODES and the status HTTP_STATUS_FOR_ERROR gives it.
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { expect, it, vi } from "vitest"
import { createProof, webCryptoSigner, type WorkspaceRef } from "@mehen/protocol"
import { ERROR_CODES, HTTP_STATUS_FOR_ERROR, type ErrorCode } from "@mehen/protocol/api"
import worker from "../../src/index.ts"
import { ROUTES } from "../../src/routes/index.ts"
import { WORKSPACE_ROUTES } from "../../src/routes/workspace-prefix.ts"
import { setUpstreamFetch } from "../../src/relay/upstream.ts"
import { ORIGIN } from "../helpers.ts"
import { body, type Machine, type Person } from "./workspace-journey.ts"
import { workloadJourney } from "../workload-journey.ts"

type Probe = { method: string; path: string; raw: string | Uint8Array<ArrayBuffer> | null; headers?: Record<string, string> }
type Fixture = Awaited<ReturnType<typeof workloadJourney>>
type Signer = { machine: Machine; device: string; keys: CryptoKeyPair; workload?: string; tenant?: string }

// The device routes the bodies below do not reach: each changes state
// whatever its body says, so it is probed only in the states that follow.
const PANIC = new Set(["POST /v1/freeze", "POST /v1/devices/self/revoke"])

// A workspace's notices reach D1 from an alarm 60 s after they are queued
// (queueNotice). On a slow host that alarm runs in a later test of this file,
// after storage was reset, finds no account and logs
// workspace.notice.write_pending for the outbox to retry. That line says
// nothing about the routes under probe; every other error line does.
function unexpectedErrors(errors: { mock: { calls: unknown[][] } }): unknown[][] {
  return errors.mock.calls.filter(([line]) => !String(line).startsWith('{"at":"workspace.notice.write_pending"'))
}
const WORKSPACE_PANIC = new Set(["POST /freeze"])

const DEEP = `${"[".repeat(5000)}${"]".repeat(5000)}`
const WRONG_TYPES = JSON.stringify({ slug: 1, item: [], project: {}, env: null, name: true, provider: 7, kind: [], home: 1, scope: "all", jwk: "x", label: {}, ttlSeconds: "1", run: 1, field: [], url: 1, method: {}, headers: "x", body: 1, change: [], input: 1, decision: 1, stepUp: "x", proposal: 1, before: 1, after: 1, project_id: null, vars: "x", argv: {}, terms: 1 })
const BAD_BODIES: { label: string; raw: string | Uint8Array<ArrayBuffer> }[] = [
  { label: "empty", raw: "" },
  { label: "truncated", raw: "{" },
  { label: "array", raw: "[]" },
  { label: "null", raw: "null" },
  { label: "number", raw: "1" },
  { label: "string", raw: "\"x\"" },
  { label: "deep", raw: DEEP },
  { label: "deep inside", raw: `{"input":${DEEP},"change":${DEEP},"scope":${DEEP},"stepUp":${DEEP}}` },
  { label: "deepest", raw: `${"[".repeat(400_000)}${"]".repeat(400_000)}` },
  { label: "proto", raw: "{\"__proto__\":{\"polluted\":true},\"constructor\":{\"prototype\":{}}}" },
  { label: "wrong types", raw: WRONG_TYPES },
  { label: "long strings", raw: JSON.stringify(Object.fromEntries(["slug", "item", "project", "name", "provider", "label", "url", "proposal", "id"].map((key) => [key, "x".repeat(100_000)]))) },
  { label: "invalid utf-8", raw: new Uint8Array([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x3a, 0x31, 0x7d]) },
]
const PARAMS = ["missing123", "x".repeat(2000), "%00", "..", "%E2%80%AE", "a%2Fb", "%F0%9F%90%8D", "%ZZ"]
const QUERIES = ["?wait=1", "?limit=-1&before=abc&cursor=%00&item=x", "?limit=1e309&before=NaN", "?tag=&kind=zzz&provider=%00", "?item=a&item=b&device=dev_x&session=y", `?cursor=${"x".repeat(5000)}`]

async function send(f: Fixture, probe: Probe, extra: Record<string, string> = {}): Promise<Response> {
  const ctx = createExecutionContext()
  const init: RequestInit<IncomingRequestCfProperties> = { method: probe.method, headers: { origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json", ...probe.headers, ...extra } }
  if (probe.raw !== null && probe.method !== "GET" && probe.method !== "HEAD") init.body = probe.raw
  const response = await worker.fetch(new Request<unknown, IncomingRequestCfProperties>(`${ORIGIN}${probe.path}`, init), f.env, ctx)
  await waitOnExecutionContext(ctx)
  return response
}

async function sendDevice(f: Fixture, signer: Signer, probe: Probe): Promise<Response> {
  const bodyForProof = probe.method === "GET" || probe.method === "HEAD" ? null : probe.raw
  const proof = await createProof(webCryptoSigner(signer.device, signer.keys.privateKey, signer.workload), { method: probe.method, url: `${ORIGIN}${probe.path}`, body: bodyForProof }, { tenant: signer.tenant ?? signer.machine.workspace.id })
  return send(f, probe, { "Mehen-Proof": proof })
}

// A refusal the vault answered as it documents, or the failure in words.
async function judge(label: string, response: Response): Promise<string | null> {
  const text = await response.text()
  if (response.status >= 500) return `${label}: ${response.status} ${text.slice(0, 200)}`
  if (response.status < 400) return null
  if (response.headers.get("Mehen-Error") !== "1") return `${label}: ${response.status} without Mehen-Error`
  let parsed: { error?: string; message?: string }
  try {
    parsed = JSON.parse(text) as { error?: string; message?: string }
  } catch {
    return `${label}: ${response.status} not JSON`
  }
  if (!(ERROR_CODES as readonly string[]).includes(parsed.error ?? "")) return `${label}: unknown code ${parsed.error}`
  const expected = HTTP_STATUS_FOR_ERROR[parsed.error as ErrorCode]
  if (expected !== response.status && !(response.status === 405 && parsed.error === "bad_request")) return `${label}: ${parsed.error} answered ${response.status}, documented ${expected}`
  if (typeof parsed.message !== "string" || parsed.message === "") return `${label}: no message`
  return null
}

function fill(path: string, value: string): string {
  return path.replace(/:[A-Za-z]+/g, value)
}

// Every bad-input variant of one route: each body, each odd path parameter
// and each odd query, with the values the fixture's own workspace and the
// other workspace use for real ids.
function variants(method: string, pattern: string, ids: string[]): Probe[] {
  const out: Probe[] = []
  const real = fill(pattern, ids[0] ?? "missing123")
  if (method === "GET" || method === "HEAD") for (const query of QUERIES) out.push({ method, path: `${real}${query}`, raw: null })
  else {
    for (const bad of BAD_BODIES) out.push({ method, path: real, raw: bad.raw })
    out.push({ method, path: real, raw: "{}", headers: { "content-type": "text/plain" } })
    out.push({ method, path: real, raw: "{}", headers: { "content-type": "application/x-www-form-urlencoded" } })
    out.push({ method, path: real, raw: new Uint8Array(1_000_001).fill(0x20) })
  }
  if (pattern.includes(":")) for (const value of [...PARAMS, ...ids]) out.push({ method, path: fill(pattern, value), raw: method === "GET" ? null : "{}" })
  return out
}

async function setUp() {
  const f = await workloadJourney()
  setUpstreamFetch(async () => new Response("probe-upstream"))
  await f.credential(f.alex, f.work, "probe-key", { kind: "workspace" })
  await f.credential(f.alex, f.personal, "foreign-key", { kind: "workspace" })
  const projectInput = { slug: "foreign", remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false, fourEyes: false }] }
  const foreignProject = await body<{ id: string }>(await f.projectMutation(f.alex, f.personal, "create", projectInput, "/projects"), 201)
  const foreignMachine = await f.enrolMachine(f.alex, f.personal)
  const run = await body<{ run: string }>(await f.deviceCall(f.machine, "/v1/runs", { project: f.project.id, env: "dev", envSource: "flag", remote: null, worktree: "/probe", head: null, vars: [], command: "node probe.js", argv: ["node", "probe.js"] }), 201)
  const workload = await f.createWorkload(f.machine, {}, "probe-task")
  // Real ids from this workspace and from the other one, as path parameters.
  const ids = [f.project.id, "probe-key", run.run, workload.view.workload, f.machine.device, "foreign-key", foreignProject.id, foreignMachine.device, "prj_missing123", "dev_missing123"]
  return { f, run, workload, ids, foreignMachine }
}

async function probeDevice(f: Fixture, signer: Signer, ids: string[], state: string, failures: string[], skip: Set<string> = PANIC) {
  for (const route of ROUTES.filter((r) => r.path.startsWith("/v1/") && !skip.has(`${r.method} ${r.path}`))) {
    for (const probe of variants(route.method, route.path, ids)) {
      const failure = await judge(`[${state}] ${probe.method} ${probe.path.slice(0, 120)} ${typeof probe.raw === "string" ? probe.raw.slice(0, 40) : probe.raw === null ? "" : `${probe.raw.byteLength} bytes`}`, await sendDevice(f, signer, probe))
      if (failure) failures.push(failure)
    }
  }
}

async function probeWorkspace(f: Fixture, person: Person, workspace: WorkspaceRef, ids: string[], state: string, failures: string[], skip: Set<string> = WORKSPACE_PANIC) {
  for (const route of WORKSPACE_ROUTES.filter((r) => !skip.has(`${r.method} ${r.path}`))) {
    for (const probe of variants(route.method, `/api/w/${workspace.slug}${route.path}`, ids)) {
      const failure = await judge(`[${state}] ${probe.method} ${probe.path.slice(0, 120)} ${typeof probe.raw === "string" ? probe.raw.slice(0, 40) : probe.raw === null ? "" : `${probe.raw.byteLength} bytes`}`, await send(f, { ...probe, headers: { cookie: person.cookie, ...probe.headers } }))
      if (failure) failures.push(failure)
    }
  }
}

it("every /v1 device route refuses bad input from a live machine as documented, never with a 500", async () => {
  const { f, ids } = await setUp()
  const errors = vi.spyOn(console, "error")
  const failures: string[] = []
  try {
    const signer: Signer = { machine: f.machine, device: f.machine.device, keys: f.machine.keys }
    await probeDevice(f, signer, ids, "live", failures)
    // The proof claims the other workspace: refused as unknown there.
    await probeDevice(f, { ...signer, tenant: f.personal.id }, ids.slice(0, 2), "foreign tenant", failures)
    // An oversized relay body, past the relay's own larger limit.
    const relay = await judge("relay 15 MB", await sendDevice(f, signer, { method: "POST", path: "/v1/relay", raw: new Uint8Array(15 * 1024 * 1024).fill(0x20) }))
    if (relay) failures.push(relay)

    expect(failures).toEqual([])
    expect(unexpectedErrors(errors)).toEqual([])
  } finally {
    errors.mockRestore()
    setUpstreamFetch(null)
  }
}, 600_000)

it("every /api/w workspace route refuses bad input from a member as documented, never with a 500", async () => {
  const { f, ids } = await setUp()
  const errors = vi.spyOn(console, "error")
  const failures: string[] = []
  try {
    await probeWorkspace(f, f.alex, f.work, ids, "member", failures)
    // Signed out, and signed in to a workspace the person is not in.
    await probeWorkspace(f, { ...f.alex, cookie: "mehen_session=forged" }, f.work, ids.slice(0, 1), "signed out", failures, new Set())
    await probeWorkspace(f, f.alex, { id: "tn_missing12345", slug: "not-a-workspace", name: "x" }, ids.slice(0, 1), "unknown workspace", failures, new Set())
    expect(failures).toEqual([])
    expect(unexpectedErrors(errors)).toEqual([])
  } finally {
    errors.mockRestore()
    setUpstreamFetch(null)
  }
}, 600_000)

it("every /v1 device route refuses an ended workload, a revoked machine and a frozen workspace as documented", async () => {
  const { f, ids, workload } = await setUp()
  const errors = vi.spyOn(console, "error")
  const failures: string[] = []
  try {
    await body(await f.deviceCall(f.machine, `/v1/workloads/${workload.view.workload}`, undefined, undefined, undefined, "DELETE"))
    await probeDevice(f, { machine: f.machine, device: f.machine.device, keys: workload.keys, workload: workload.view.workload }, ids.slice(0, 4), "ended workload", failures, new Set())
    const spare = await f.enrolMachine(f.alex, f.work)
    await body(await f.deviceCall(spare, "/v1/devices/self/revoke", {}))
    await probeDevice(f, { machine: spare, device: spare.device, keys: spare.keys }, ids.slice(0, 4), "revoked machine", failures, new Set())
    // A member who has been removed: their machine, and their browser.
    const kim = await f.guest(f.alex, f.work, f.project.id, "Kim")
    await body(await f.memberChange(f.alex, f.work, kim.member!, "role", "admin"))
    const kimMachine = await f.enrolMachine(kim, f.work)
    await body(await f.memberChange(f.alex, f.work, kim.member!, "remove"))
    await probeDevice(f, { machine: kimMachine, device: kimMachine.device, keys: kimMachine.keys }, ids.slice(0, 4), "removed member", failures, new Set())
    await probeWorkspace(f, kim, f.work, ids.slice(0, 2), "removed member", failures, new Set())
    expect((await f.deviceCall(f.machine, "/v1/freeze", "{")).status).toBeLessThan(500)
    const frozen: Signer = { machine: f.machine, device: f.machine.device, keys: f.machine.keys }
    await probeDevice(f, frozen, ids.slice(0, 4), "frozen", failures, new Set(["POST /v1/devices/self/revoke"]))
    await probeWorkspace(f, f.alex, f.work, ids.slice(0, 4), "frozen", failures, new Set())
    // Last, since any body revokes the machine: a panic button is never refused for its body.
    await probeDevice(f, frozen, ids.slice(0, 4), "frozen", failures, new Set(ROUTES.map((r) => `${r.method} ${r.path}`).filter((route) => route !== "POST /v1/devices/self/revoke")))
    expect(failures).toEqual([])
    expect(unexpectedErrors(errors)).toEqual([])
  } finally {
    errors.mockRestore()
    setUpstreamFetch(null)
  }
}, 600_000)
