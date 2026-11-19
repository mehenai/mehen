import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { verifyAuditChain, type AuditRow } from "../src/vault/audit.ts"
import { fetchWorker, freshTenant, invoke, owner, system } from "./helpers.ts"

describe("worker", () => {
  it("answers health checks with security headers", async () => {
    const res = await fetchWorker("/healthz")
    expect(res.status).toBe(200)
    expect(res.headers.get("cache-control")).toBe("no-store")
    expect(res.headers.get("x-frame-options")).toBe("DENY")
  })

  it("publishes the seal key", async () => {
    const res = await fetchWorker("/v1/seal-key")
    const body = (await res.json()) as { jwk: { kty: string; d?: string }; kid: string }
    expect(body.jwk.kty).toBe("EC")
    expect(body.jwk.d).toBeUndefined()
    expect(body.kid).toHaveLength(16)
  })

  it("refuses unknown routes and device calls without a proof as JSON with Mehen-Error", async () => {
    const missing = await fetchWorker("/nope")
    expect(missing.status).toBe(404)
    expect(missing.headers.get("mehen-error")).toBe("1")
    const me = await fetchWorker("/v1/me")
    expect(me.status).toBe(401)
    const body = (await me.json()) as { error: string; next?: { command?: string } }
    expect(body.error).toBe("unauthenticated")
    expect(body.next?.command).toBe("mehen enrol --workspace <slug>")
  })

  it("has the directory tables", async () => {
    const tables = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all<{ name: string }>()
    expect(tables.results.map((r) => r.name)).toEqual(expect.arrayContaining(["accounts", "workspaces", "memberships", "passkeys", "enrolments", "workspace_cutover"]))
  })
})

describe("workspace vault core", () => {
  it("refuses unknown ops and the wrong principal", async () => {
    const tenant = freshTenant()
    const unknown = await invoke(tenant, system("nope.op"))
    expect(unknown.ok).toBe(false)
    const audit = await invoke(tenant, system("tenant.audit"))
    expect(audit).toMatchObject({ ok: false, error: { vaultError: { error: "forbidden" } } })
  })

  it("seals and opens fields bound to tenant, type and id", async () => {
    const tenant = freshTenant()
    const stub = env.TENANT_VAULT.getByName(tenant)
    await runInDurableObject(stub, async (instance) => {
      const ctx = instance.context
      const sealed = await ctx.sealField({ type: "field", id: "itm_a/key" }, new Uint8Array(new TextEncoder().encode("sk-secret")))
      const opened = await ctx.openField({ type: "field", id: "itm_a/key" }, sealed)
      expect(new TextDecoder().decode(opened)).toBe("sk-secret")
      await expect(ctx.openField({ type: "field", id: "itm_b/key" }, sealed)).rejects.toThrow()
    })
  })
})

it("the live area registry has no legacy ops maps",async () => {
  const { AREAS } = await import("../src/vault/registry.ts")
  for (const area of AREAS) expect(Object.hasOwn(area,"ops"),area.name).toBe(false)
})

it("every literal test path named by a vault script exists",() => {
  const scripts = import.meta.glob<string>("../scripts/*.ts",{ query: "?raw",import: "default",eager: true })
  const tests = import.meta.glob<string>(["../test/**/*.test.ts","../src/**/*.test.ts"],{ query: "?raw",import: "default",eager: true })
  for (const [script,source] of Object.entries(scripts)) for (const match of source.matchAll(/["'`](test\/[^"'`]+\.test\.ts)["'`]/g)) expect(Object.hasOwn(tests,`../${match[1]}`),`${script}: ${match[1]}`).toBe(true)
})
