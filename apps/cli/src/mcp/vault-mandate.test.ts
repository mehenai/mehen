import { expect, test } from "bun:test"
import { z } from "zod"
import type { VaultSession } from "../session.ts"
import { mandateCreated, mandateOpenProposal, mandateReceipt, mandateView } from "../testing/mandate-fixtures.ts"
import { type VaultApi, VaultApiError } from "../vault-api.ts"
import { CallRegistry } from "./call-registry.ts"
import type { ToolDeps } from "./shared.ts"
import { vaultMandate } from "./vault-mandate.ts"

const call = { signal: new AbortController().signal, progressToken: null }
const VAULT = "https://vault.example"
function deps(api: VaultApi): ToolDeps {
  const configDir = "/unused"
  const config = { vault: VAULT, tenant: "ten_test", device: "dev_test", backend: "software" as const, workspaceSlug: "test-space", workspaceName: "Test Space" }
  const session: VaultSession = { api, config, vaultUrl: config.vault, configDir, selection: { dir: configDir, config, reason: "workspace" }, ledger: { vaultUrl: config.vault, workspace: config.tenant, device: config.device, workspaceSlug: "test-space" }, context: { origin: config.vault, workspace: null, device: config.device } }
  const server = { home: "/unused", managed: null, ceiling: null, allowed: null, pin: null, manifest: null, slots: new Map(), seen: new Map(), realRoot: "/unused" }
  return { env: {}, server, apps: { negotiated: false }, used: null, session: async () => session, span: async () => ({ active: [], pending: [], corrupt: [], absent: [] }), open: async () => session, validate: async () => config, notify: () => {}, calls: new CallRegistry() }
}

type Seen = { method: string; path: string; body: unknown }
function vault(answer: (seen: Seen) => unknown): { api: VaultApi; seen: Seen[] } {
  const seen: Seen[] = []
  const api: VaultApi = {
    request: async <T>(method: string, path: string, body?: unknown) => {
      const request = { method, path, body }
      seen.push(request)
      if (path === "/v1/me") return { name: "test-machine" } as T
      return answer(request) as T
    },
    relay: async () => { throw new Error("unexpected relay") },
  }
  return { api, seen }
}

test("vault_mandate has a closed object-root input schema with the five machine actions and no way to sign, resume or stop", () => {
  const schema = z.toJSONSchema(vaultMandate.input, { io: "input" })
  expect(schema.type).toBe("object")
  for (const key of ["oneOf", "anyOf", "allOf"]) expect(schema).not.toHaveProperty(key)
  expect((schema.properties as { action: { enum: string[] } }).action.enum).toEqual(["propose", "list", "show", "uses", "pause"])
  expect(vaultMandate.description).toContain("Agents cannot sign, resume or stop a mandate")
  expect(vaultMandate.description).toContain("A mandate never covers credential, access or money changes, nor anything an ask's mandateCover says it cannot.")
})

test("refusal/vault_mandate refuses resume, stop, sign, stray fields and terms the protocol would refuse before session or network", async () => {
  const { api, seen } = vault(() => { throw new Error("unexpected request") })
  let sessions = 0
  const dependencies = { ...deps(api), session: async () => { sessions++; throw new Error("unexpected session") } }
  for (const value of [
    { action: "resume", id: "mdt_live" },
    { action: "stop", id: "mdt_live" },
    { action: "sign", id: "mdp_new" },
    { action: "propose" },
    { action: "propose", note: "x", id: "mdt_live" },
    { action: "propose", note: "x", items: ["all", "github-work"] },
    { action: "propose", note: "x", classes: ["read"], caps: { send: 5 } },
    { action: "propose", note: "x", schedule: "Europe/Paris someday 08:00-19:00" },
    { action: "list", id: "mdt_live" },
    { action: "show", id: "pol_live" },
    { action: "pause", id: "pol_live" },
    { action: "uses", id: "mdt_live", since: "yesterday" },
  ]) {
    await expect(vaultMandate.call(value, dependencies, call), JSON.stringify(value)).rejects.toMatchObject({ code: "usage" })
  }
  expect(sessions).toBe(0)
  expect(seen).toEqual([])
})

test("propose sends the protocol's terms and hands over the sign page, with a then: that lists rather than waits", async () => {
  const { api, seen } = vault(() => mandateCreated(VAULT, "test-space"))
  const result = await vaultMandate.call({ action: "propose", note: "Nightly triage", items: ["linear-work", "github-work"], classes: ["send"], caps: { send: 20 }, days: 7, schedule: "UTC daily 22:00-06:00" }, { ...deps(api), env: { MEHEN_SESSION: "triage-1" } }, call)
  expect(seen.map((s) => s.path)).toEqual(["/v1/me", "/v1/mandates/proposals"])
  expect(seen.find((s) => s.path === "/v1/mandates/proposals")?.body).toEqual({ terms: { items: ["github-work", "linear-work"], classes: ["read", "send"], caps: { read: 5000, change: 0, send: 20, delete: 0 }, ttlDays: 7, schedule: { tz: "UTC", windows: [{ days: [0, 1, 2, 3, 4, 5, 6], from: "22:00", to: "06:00" }] }, note: "Nightly triage" }, reason: "Nightly triage" })
  const url = `${VAULT}/w/test-space/sign-mandate?proposal=mdp_new`
  expect(result.structured).toMatchObject({ proposal: "mdp_new", url, warning: null })
  expect(result.handover).toMatchObject([{ ask: { kind: "mandate", id: "mdp_new", url, wait: null, requestedBy: { device: "test-machine", session: "triage-1" } }, then: 'vault_mandate { "action": "list" } shows it again while it is open, and the mandate once it is signed' }])
  const again = await vaultMandate.call({ action: "propose", note: "Nightly triage" }, deps(vault(() => ({ ...mandateCreated(VAULT, "test-space"), existing: true })).api), call)
  expect(again.structured).toMatchObject({ proposal: "mdp_new", existing: true })
  expect(again.handover[0]?.then).toStartWith("these terms are already waiting for the person to sign; this is the same link.")
})

test("list, show, uses and pause each read the machine's own view, without signerCurrent, and hand nothing over", async () => {
  const leaked = { ...mandateView(), signerCurrent: true }
  const { api, seen } = vault(({ method, path }) => {
    if (path === "/v1/mandates") return { mandates: [leaked], proposals: [mandateOpenProposal(VAULT, "test-space")] }
    if (path === "/v1/mandates/mdt_live") return leaked
    if (path === "/v1/mandates/mdt_live/uses") return { receipts: [mandateReceipt()], next: null }
    if (method === "POST" && path === "/v1/mandates/mdt_live/pause") return { mandate: { ...leaked, state: "paused", rev: 3 } }
    throw new Error(`unexpected ${path}`)
  })
  const run = (value: Record<string, unknown>) => vaultMandate.call(value, deps(api), call)
  const listed = await run({ action: "list" })
  expect(JSON.stringify(listed.structured)).not.toContain("signerCurrent")
  expect(listed.handover).toEqual([])
  expect(listed.structured).toMatchObject({ proposals: [{ id: "mdp_open", url: `${VAULT}/w/test-space/sign-mandate?proposal=mdp_open`, reason: "Tickets keep coming" }] })
  expect(await run({ action: "show", id: "mdt_live" })).toMatchObject({ structured: { id: "mdt_live", state: "active" } })
  expect((await run({ action: "uses", id: "mdt_live" })).structured).toMatchObject({ mandate: "mdt_live", receipts: [{ id: "mdu_1" }] })
  const paused = await run({ action: "pause", id: "mdt_live" })
  expect(paused.structured).toMatchObject({ mandate: { state: "paused", rev: 3 }, said: expect.stringContaining("they need no passkey") })
  expect(JSON.stringify(paused.structured)).not.toContain("signerCurrent")
  expect(seen.filter((s) => s.path.endsWith("/pause")).map((s) => s.body)).toEqual([{ rev: 2 }])
})

test("show and list hand over the page of a paused, tripped or ended mandate in next.url, for the person who signed it", async () => {
  const page = `${VAULT}/w/test-space/mandates/mdt_live`
  for (const view of [mandateView({ state: "paused" }), mandateView({ state: "tripped" }), mandateView({ state: "expired" })]) {
    const { api } = vault(({ path }) => (path === "/v1/mandates" ? { mandates: [view], proposals: [] } : view))
    expect((await vaultMandate.call({ action: "show", id: "mdt_live" }, deps(api), call)).structured, view.state).toMatchObject({ state: view.state, next: { url: page } })
    expect((await vaultMandate.call({ action: "list" }, deps(api), call)).structured, view.state).toMatchObject({ next: { url: page } })
  }
  const { api } = vault(() => mandateView())
  expect((await vaultMandate.call({ action: "show", id: "mdt_live" }, deps(api), call)).structured).not.toHaveProperty("next")
})

test("uses stops at 500 receipts with truncated and the cursor to carry on from; before carries on from it, and since bounds it first", async () => {
  const start = Date.parse("2026-11-08T12:00:00.000Z")
  const receipts = Array.from({ length: 640 }, (_, i) => mandateReceipt({ id: `mdu_${String(i).padStart(3, "0")}`, at: new Date(start - i * 1000).toISOString() }))
  const cursorOf = (r: { at: string; id: string }) => `${Date.parse(r.at)}.${r.id}`
  const { api } = vault(({ path }) => {
    const before = /\?before=(.+)$/.exec(path)?.[1]
    const from = before === undefined ? 0 : receipts.findIndex((r) => cursorOf(r) === decodeURIComponent(before)) + 1
    const page = receipts.slice(from, from + 100)
    return { receipts: page, next: from + 100 < receipts.length ? cursorOf(page.at(-1) as { at: string; id: string }) : null }
  })
  const run = async (value: Record<string, unknown>) => (await vaultMandate.call({ action: "uses", id: "mdt_live", ...value }, deps(api), call)).structured as { receipts: { id: string }[]; truncated: boolean; next: string | null }
  const first = await run({})
  expect(first.receipts.length).toBe(500)
  expect(first).toMatchObject({ truncated: true, next: cursorOf(receipts[499] as { at: string; id: string }) })
  const rest = await run({ before: first.next })
  expect(rest.receipts.map((r) => r.id)).toEqual(receipts.slice(500).map((r) => r.id))
  expect(rest).toMatchObject({ truncated: false, next: null })
  const recent = await run({ since: new Date(start - 299_500).toISOString() })
  expect(recent.receipts.length).toBe(300)
  expect(recent).toMatchObject({ truncated: false, next: null })
  await expect(vaultMandate.call({ action: "uses", id: "mdt_live", before: "yesterday" }, deps(api), call)).rejects.toMatchObject({ code: "usage" })
})

test("pause without id pauses this machine's live mandate, and refuses when there is none", async () => {
  const { api, seen } = vault(({ method, path }) => {
    if (path === "/v1/mandates") return { mandates: [mandateView({ rev: 7 })], proposals: [] }
    if (path === "/v1/mandates/mdt_live") return mandateView({ rev: 7 })
    if (method === "POST" && path === "/v1/mandates/mdt_live/pause") return { mandate: mandateView({ state: "paused", rev: 8 }) }
    throw new Error(`unexpected ${path}`)
  })
  const paused = await vaultMandate.call({ action: "pause" }, deps(api), call)
  expect(paused.structured).toMatchObject({ mandate: { id: "mdt_live", state: "paused" }, next: { url: `${VAULT}/w/test-space/mandates/mdt_live` } })
  expect(seen.filter((s) => s.path.endsWith("/pause")).map((s) => s.body)).toEqual([{ rev: 7 }])
  const empty = vault(() => ({ mandates: [], proposals: [] }))
  await expect(vaultMandate.call({ action: "pause" }, deps(empty.api), call)).rejects.toMatchObject({ code: "not_found" })
  expect(empty.seen.filter((s) => s.path.endsWith("/pause"))).toEqual([])
})

test("refusal/the 3-open, no-live and several-live refusals name vault_mandate with its arguments, never a mehen command", async () => {
  const newest = `${VAULT}/w/test-space/sign-mandate?proposal=mdp_newest`
  const full = vault(() => { throw new VaultApiError(409, { error: "conflict", message: "This machine already has 3 mandates waiting for a person.", next: { url: newest, say: "x" } }) })
  const refused = await vaultMandate.call({ action: "propose", note: "Nightly triage" }, deps(full.api), call).catch((error: unknown) => error)
  expect(refused).toMatchObject({ code: "conflict", next: { url: newest, say: `This machine's proposals are still waiting for its signer; vault_mandate { "action": "list" } lists every open one, and the newest is at ${newest}. Hand a link to the person rather than proposing again.` } })
  expect((refused as { next: object }).next).not.toHaveProperty("command")
  const none = await vaultMandate.call({ action: "pause" }, deps(vault(() => ({ mandates: [], proposals: [] })).api), call).catch((error: unknown) => error)
  expect(none).toMatchObject({ code: "not_found", next: { say: expect.stringContaining('vault_mandate { "action": "list" } lists') } })
  expect((none as { next: object }).next).not.toHaveProperty("command")
  const several = await vaultMandate.call({ action: "pause" }, deps(vault(() => ({ mandates: [mandateView({ id: "mdt_a" }), mandateView({ id: "mdt_b", state: "paused" })], proposals: [] })).api), call).catch((error: unknown) => error)
  expect(several).toMatchObject({ code: "conflict", next: { say: 'Pause each with vault_mandate { "action": "pause", "id": "<mdt_id>" }, such as mdt_a.' } })
  expect((several as { next: object }).next).not.toHaveProperty("command")
  for (const error of [refused, none, several]) expect(JSON.stringify((error as { next: unknown }).next)).not.toContain("mehen ")
})
