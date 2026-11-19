import { seedRelayProject,seedRelayVar,seedRelayEnvironment } from "./relay-fixtures.ts"
import { newPlaceholder } from "@mehen/protocol"
// Host fences are enforced by the vault, not only by the local relay.
// A run's placeholder never reaches a host fenced to
// another environment of its project, whether the request came through the
// local relay, mehen fetch --run or vault_fetch with a run. The refusal is a
// tripwire in the audit log, with hosts and item names only.

import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import type { RelayRequestInput } from "@mehen/protocol/api"
import { VaultError } from "../src/http.ts"
import type { RelayMaterial } from "../src/relay/forward.ts"
import { items } from "../src/vault/areas/items.ts"
import { type SetEnvironmentInput, type SetVarInput } from "../src/vault/areas/projects.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import { runs } from "../src/vault/areas/runs.ts"
import type { DevicePrincipal, VaultContext } from "../src/vault/core.ts"
import { freshTenant, testDevice as fabricatedDevice } from "./helpers.ts"

import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"
const testDevice = (overrides: Parameters<typeof fabricatedDevice>[0] = {}) => fabricatedDevice({ device: POLICY_DEVICE, ...overrides })

const SYSTEM = { kind: "system", reason: "test" } as const
const API_KEY = "sk-proj-examplekeyexamplekeyexample"
const DEVICE = testDevice()

async function refusal(promise: Promise<unknown>): Promise<VaultError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof VaultError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

function setVar(ctx: VaultContext,change: SetVarInput) { seedRelayVar(ctx,change) }
function setEnvironment(ctx: VaultContext,change: SetEnvironmentInput) { seedRelayEnvironment(ctx,change) }

function authorise(ctx: VaultContext, device: DevicePrincipal, input: RelayRequestInput): Promise<RelayMaterial> {
  return authoriseRelay(ctx, device, input) as Promise<RelayMaterial>
}

// A project "foo" with dev, staging and a protected prod. EXAMPLE_KEY in dev
// and staging is "example-api", bound to *.example.com. prod fences
// *.prod.example.com, staging fences staging.example.com and dev fences
// dev.example.com.
async function setUp(ctx: VaultContext): Promise<string> {
  await items.putItem(
    ctx,
    {
      slug: "example-api",
      kind: "api-key",
      provider: null,
      account: null,
      accountVerified: false,
      tags: ["personal"],
      ceiling: "placeholder",
      binding: { hosts: ["*.example.com"] },
      policy: { default: "allow", rules: [] },
      injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
      publicFields: {},
      secretFields: { key: API_KEY },
      description: null,
    },
    SYSTEM,
  )
  const id = seedRelayProject(ctx,{
    slug: "foo",
    remote: "github.com/example/foo",
    environments: [
      { name: "dev", protected: false },
      { name: "staging", protected: false },
      { name: "prod", protected: true },
    ],
    defaultEnv: "dev",
  })
  for (const envName of ["dev", "staging"]) await setVar(ctx, { project: id, env: envName, name: "EXAMPLE_KEY", item: "example-api" })
  await setEnvironment(ctx, { project: id, env: "prod", protected: true, fences: ["*.prod.example.com"] })
  await setEnvironment(ctx, { project: id, env: "staging", protected: false, fences: ["staging.example.com"] })
  await setEnvironment(ctx, { project: id, env: "dev", protected: false, fences: ["dev.example.com"] })
  return id
}

async function startRun(ctx: VaultContext, project: string, envName: string): Promise<{ run: string; placeholder: string; created: { fencedHosts: string[] } }> {
  const run = `run_${crypto.randomUUID()}`,placeholder = newPlaceholder("shared-relay-test")
  ctx.sql.exec("INSERT INTO runs(id,device,project,env,remote,worktree,command,created_at,expires_at) VALUES (?,?,?,?,?,'/test','test',?,?)",run,DEVICE.device,project,envName,"github.com/example/foo",ctx.now(),ctx.now()+60_000)
  ctx.sql.exec("INSERT INTO run_placeholders(placeholder,run,item,field,hosts) VALUES (?,?,'example-api','key','[\"*.example.com\"]')",placeholder,run)
  return { run,placeholder,created: { fencedHosts: runs.fencesFor(ctx,DEVICE,run)?.fencedHosts ?? [] } }
}

function request(run: string, url: string, placeholder: string | null): RelayRequestInput {
  return { run, method: "GET", url, headers: placeholder === null ? [] : [["Authorization", `Bearer ${placeholder}`]] }
}

function inVault(fn: (ctx: VaultContext) => Promise<void>): Promise<void> {
  return runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => { await registerPolicyDevice(instance.context, testDevice()); await fn(instance.context) })
}

type AuditRow = { action: string; target: string | null; detail: string }

function auditRows(ctx: VaultContext, action: string): AuditRow[] {
  return ctx.sql.exec<AuditRow>("SELECT action, target, detail FROM audit WHERE action = ?", action).toArray()
}

function auditText(ctx: VaultContext): string {
  return JSON.stringify(ctx.sql.exec("SELECT * FROM audit").toArray())
}

describe("host fences at the vault relay", () => {
  it("refuses a dev run's placeholder to a host fenced to prod, with a tripwire that names hosts and items only", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      const { run, placeholder, created } = await startRun(ctx, project, "dev")
      expect(created.fencedHosts).toEqual(["*.prod.example.com", "staging.example.com"])

      const refused = await refusal(authorise(ctx, DEVICE, request(run, "https://api.prod.example.com/v1/charges", placeholder)))
      expect(refused.code).toBe("environment_refused")
      expect(refused.message).toContain("api.prod.example.com")
      expect(refused.message).toContain("env=dev")

      const [tripwire, ...more] = auditRows(ctx, "relay.tripwire")
      expect(more).toEqual([])
      expect(tripwire?.target).toBe("example-api")
      expect(JSON.parse(tripwire?.detail ?? "{}")).toEqual({
        run,
        host: "api.prod.example.com",
        method: "GET",
        items: ["example-api"],
        fences: ["*.prod.example.com"],
        reason: "fenced-host",
      })
      expect(auditRows(ctx, "relay.allow")).toEqual([])
      const audit = auditText(ctx)
      expect(audit).not.toContain(placeholder)
      expect(audit).not.toContain(API_KEY)
    })
  })

  it("refuses an exact fence of another unprotected environment, and a trailing-dot or upper-case spelling of a fenced host", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      const { run, placeholder } = await startRun(ctx, project, "dev")
      for (const url of ["https://staging.example.com/v1", "https://API.PROD.example.com./v1"]) {
        expect((await refusal(authorise(ctx, DEVICE, request(run, url, placeholder)))).code).toBe("environment_refused")
      }
      expect(auditRows(ctx, "relay.tripwire")).toHaveLength(2)
    })
  })

  it("refuses a fenced host even when the request carries no placeholder, before anything else is said about it", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      const { run } = await startRun(ctx, project, "dev")
      expect((await refusal(authorise(ctx, DEVICE, request(run, "https://db.prod.example.com/", null)))).code).toBe("environment_refused")
      const [tripwire] = auditRows(ctx, "relay.tripwire")
      expect(JSON.parse(tripwire?.detail ?? "{}")).toMatchObject({ host: "db.prod.example.com", items: [] })
    })
  })

  it("lets the same placeholder reach its bound hosts that no other environment fences, and its own environment's fence", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      const { run, placeholder } = await startRun(ctx, project, "dev")
      for (const url of ["https://api.example.com/v1/models", "https://dev.example.com/v1/models"]) {
        const material = await authorise(ctx, DEVICE, request(run, url, placeholder))
        expect(material.headers).toContainEqual(["authorization", `Bearer ${API_KEY}`])
      }
      expect(auditRows(ctx, "relay.tripwire")).toEqual([])
    })
  })

  it("fences a staging run from dev's hosts, so the fence follows the run's environment", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      const { run, placeholder } = await startRun(ctx, project, "staging")
      expect((await refusal(authorise(ctx, DEVICE, request(run, "https://dev.example.com/v1", placeholder)))).code).toBe("environment_refused")
      await authorise(ctx, DEVICE, request(run, "https://staging.example.com/v1", placeholder))
    })
  })

  it("reads the fences on every request, so a fence added mid-run applies at once", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      const { run, placeholder } = await startRun(ctx, project, "dev")
      await authorise(ctx, DEVICE, request(run, "https://billing.example.com/v1", placeholder))
      await setEnvironment(ctx, { project, env: "prod", protected: true, fences: ["*.prod.example.com", "billing.example.com"] })
      expect((await refusal(authorise(ctx, DEVICE, request(run, "https://billing.example.com/v1", placeholder)))).code).toBe("environment_refused")
    })
  })

  it("gives the fences only of this device's live run", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      const { run } = await startRun(ctx, project, "dev")
      expect(runs.fencesFor(ctx, DEVICE, run)).toEqual({ env: "dev", fencedHosts: ["*.prod.example.com", "staging.example.com"] })
      expect(runs.fencesFor(ctx, testDevice({ device: "dev_other" }), run)).toBeNull()
      ctx.sql.exec("UPDATE runs SET ended_at=? WHERE id=?",ctx.now(),run)
      expect(runs.fencesFor(ctx, DEVICE, run)).toBeNull()
    })
  })
})
