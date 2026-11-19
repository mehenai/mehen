import { seedRelayProject,seedRelayVar,seedRelayEnvironment } from "./relay-fixtures.ts"
// Host fences hold in item mode too. A request
// that names an item, with no run, is refused with environment_refused and a
// relay.tripwire when the host matches a fence of any environment, of any
// project, unless the item backs a variable in that very environment.

import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import type { RelayRequestInput } from "@mehen/protocol/api"
import { VaultError } from "../src/http.ts"
import type { RelayMaterial } from "../src/relay/forward.ts"
import { items } from "../src/vault/areas/items.ts"
import { type SetEnvironmentInput, type SetVarInput, fencesAgainstItem } from "../src/vault/areas/projects.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { freshTenant, testDevice as fabricatedDevice } from "./helpers.ts"

import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"
const testDevice = (overrides: Parameters<typeof fabricatedDevice>[0] = {}) => fabricatedDevice({ device: POLICY_DEVICE, ...overrides })

const SYSTEM = { kind: "system", reason: "test" } as const
const API_KEY = "sk-proj-examplekeyexamplekeyexample"
const OTHER_KEY = "sk-proj-otherkeyotherkeyotherkey12"
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

function authorise(ctx: VaultContext, input: RelayRequestInput): Promise<RelayMaterial> {
  return authoriseRelay(ctx, DEVICE, input) as Promise<RelayMaterial>
}

function request(item: string, url: string): RelayRequestInput {
  return { item, method: "GET", url, headers: [] }
}

async function putApiKey(ctx: VaultContext, slug: string, key: string): Promise<void> {
  await items.putItem(
    ctx,
    {
      slug,
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
      secretFields: { key },
      description: null,
    },
    SYSTEM,
  )
}

async function createProject(ctx: VaultContext, slug: string, environments: { name: string; protected: boolean }[], defaultEnv: string): Promise<string> {
  return seedRelayProject(ctx,{ slug,remote: null,environments,defaultEnv })
}

// Project "foo": dev, staging and a protected prod. "example-api" backs
// EXAMPLE_KEY in dev and staging; "other-api" backs nothing. prod fences
// *.prod.example.com, staging fences staging.example.com and dev fences
// dev.example.com. Both items are bound to *.example.com.
async function setUp(ctx: VaultContext): Promise<string> {
  await putApiKey(ctx, "example-api", API_KEY)
  await putApiKey(ctx, "other-api", OTHER_KEY)
  const id = await createProject(
    ctx,
    "foo",
    [
      { name: "dev", protected: false },
      { name: "staging", protected: false },
      { name: "prod", protected: true },
    ],
    "dev",
  )
  for (const envName of ["dev", "staging"]) await setVar(ctx, { project: id, env: envName, name: "EXAMPLE_KEY", item: "example-api" })
  await setEnvironment(ctx, { project: id, env: "prod", protected: true, fences: ["*.prod.example.com"] })
  await setEnvironment(ctx, { project: id, env: "staging", protected: false, fences: ["staging.example.com"] })
  await setEnvironment(ctx, { project: id, env: "dev", protected: false, fences: ["dev.example.com"] })
  return id
}

function inVault(fn: (ctx: VaultContext) => Promise<void>): Promise<void> {
  return runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => { await registerPolicyDevice(instance.context, testDevice()); await fn(instance.context) })
}

type AuditRow = { action: string; target: string | null; detail: string }

function auditRows(ctx: VaultContext, action: string): AuditRow[] {
  return ctx.sql.exec<AuditRow>("SELECT action, target, detail FROM audit WHERE action = ?", action).toArray()
}

function lastUsed(ctx: VaultContext, slug: string): number | null {
  return ctx.sql.exec<{ last_used_at: number | null }>("SELECT last_used_at FROM items WHERE slug = ?", slug).one().last_used_at
}

describe("host fences in item mode", () => {
  it("refuses a dev item named directly to a host fenced to prod, with a tripwire and before anything is decrypted", async () => {
    await inVault(async (ctx) => {
      await setUp(ctx)
      const refused = await refusal(authorise(ctx, request("example-api", "https://api.prod.example.com/v1/charges")))
      expect(refused.code).toBe("environment_refused")
      expect(refused.message).toContain("api.prod.example.com")
      expect(refused.message).toContain('"example-api"')

      const [tripwire, ...more] = auditRows(ctx, "relay.tripwire")
      expect(more).toEqual([])
      expect(tripwire?.target).toBe("example-api")
      expect(JSON.parse(tripwire?.detail ?? "{}")).toEqual({
        host: "api.prod.example.com",
        method: "GET",
        items: ["example-api"],
        fences: ["*.prod.example.com"],
        reason: "fenced-host",
      })
      expect(auditRows(ctx, "relay.allow")).toEqual([])
      expect(lastUsed(ctx, "example-api")).toBeNull()
      expect(JSON.stringify(ctx.sql.exec("SELECT * FROM audit").toArray())).not.toContain(API_KEY)
    })
  })

  it("lets an item reach the fences of the environments it backs a variable in, and unfenced bound hosts", async () => {
    await inVault(async (ctx) => {
      await setUp(ctx)
      for (const url of ["https://dev.example.com/v1", "https://staging.example.com/v1", "https://api.example.com/v1"]) {
        const material = await authorise(ctx, request("example-api", url))
        expect(material.headers).toContainEqual(["authorization", `Bearer ${API_KEY}`])
      }
      expect(auditRows(ctx, "relay.tripwire")).toEqual([])
    })
  })

  it("holds an item that backs no variable off every fenced host, in any spelling", async () => {
    await inVault(async (ctx) => {
      await setUp(ctx)
      expect(fencesAgainstItem(ctx, "other-api")).toEqual(["*.prod.example.com", "dev.example.com", "staging.example.com"])
      for (const url of ["https://dev.example.com/v1", "https://STAGING.example.com./v1", "https://db.prod.example.com/"]) {
        expect((await refusal(authorise(ctx, request("other-api", url)))).code).toBe("environment_refused")
      }
      expect(auditRows(ctx, "relay.tripwire")).toHaveLength(3)
      expect(lastUsed(ctx, "other-api")).toBeNull()
      await authorise(ctx, request("other-api", "https://api.example.com/v1"))
    })
  })

  it("applies the fences of another project, whose environments the item backs nothing in", async () => {
    await inVault(async (ctx) => {
      await setUp(ctx)
      const bar = await createProject(ctx, "bar", [{ name: "dev", protected: false }, { name: "live", protected: false }], "dev")
      await setEnvironment(ctx, { project: bar, env: "live", protected: false, fences: ["billing.example.com"] })
      expect(fencesAgainstItem(ctx, "example-api")).toEqual(["*.prod.example.com", "billing.example.com"])
      expect((await refusal(authorise(ctx, request("example-api", "https://billing.example.com/v1")))).code).toBe("environment_refused")
      await setVar(ctx, { project: bar, env: "live", name: "EXAMPLE_KEY", item: "example-api" })
      await authorise(ctx, request("example-api", "https://billing.example.com/v1"))
    })
  })

  it("reads the fences on every request, so a fence added later applies at once", async () => {
    await inVault(async (ctx) => {
      const project = await setUp(ctx)
      await authorise(ctx, request("example-api", "https://payments.example.com/v1"))
      await setEnvironment(ctx, { project, env: "prod", protected: true, fences: ["*.prod.example.com", "payments.example.com"] })
      expect((await refusal(authorise(ctx, request("example-api", "https://payments.example.com/v1")))).code).toBe("environment_refused")
    })
  })
})
