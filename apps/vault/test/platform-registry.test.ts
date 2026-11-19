// The platform directory as a managed workspace reads it
// (src/platform/registry.ts readManagedPlatform).

import { describe, expect, it } from "vitest"
import { DEFAULT_PLATFORM_LIMITS, INITIAL_PLATFORM_DEFAULTS } from "@mehen/protocol"
import { readManagedPlatform } from "../src/platform/registry.ts"
import { addSubject, platformEnv, registerPlatform } from "./platform-fixtures.ts"

describe("readManagedPlatform", () => {
  it("answers the workspace's platform and its own status in one read, and null for a workspace no platform owns", async () => {
    const { env } = await platformEnv()
    const platform = await registerPlatform(env, { limits: { devicesPerSubject: 4 } })
    const tenant = await addSubject(env, platform.id, "subject-aaaa", "deleting")
    expect(await readManagedPlatform(env.DB, tenant)).toEqual({
      platform: { id: platform.id, slug: platform.slug, name: `Platform ${platform.slug}`, status: "active", removing: false, limits: { ...DEFAULT_PLATFORM_LIMITS, devicesPerSubject: 4 }, defaults: INITIAL_PLATFORM_DEFAULTS, defaultsRevision: 1 },
      workspace: { status: "deleting", subject: "subject-aaaa" },
    })
    expect(await readManagedPlatform(env.DB, "tn_Alpha123456")).toBeNull()
  })

  it("reads a retirement whose date has passed as a suspension", async () => {
    const { env } = await platformEnv()
    const now = Date.now()
    const retiring = await registerPlatform(env, { status: "retiring", retireAfter: now + 60_000 })
    const tenant = await addSubject(env, retiring.id, "subject-aaaa")
    expect((await readManagedPlatform(env.DB, tenant, now))?.platform.status).toBe("retiring")
    expect((await readManagedPlatform(env.DB, tenant, now + 60_000))?.platform.status).toBe("suspended")
  })
})
