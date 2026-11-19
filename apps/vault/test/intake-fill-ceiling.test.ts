// A password-login intake's "How may agents use it?" choice: the person's
// signed submission alone sets the fill ceiling (IntakeSubmission.ceiling in
// intake.ts, submitWorkspaceIntake in intake-workspace.ts). A machine cannot
// name it, a rotation, another kind, the switch off or a managed workspace
// refuse it before anything is stored, and a submission without it signs
// and stores exactly what it did before.

import { describe, expect, it } from "vitest"
import { canonicalJson, CredentialHomeSchema, PrivateEventSchema } from "@mehen/protocol"
import type { VaultContext } from "../src/vault/core.ts"
import { checkedCredential } from "../src/vault/areas/items-workspace.ts"
import { stepUpDigest } from "../src/vault/areas/items.ts"
import { IntakeSubmission } from "../src/vault/areas/intake.ts"
import { createWorkspaceIntake, submitWorkspaceIntake } from "../src/vault/areas/intake-workspace.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { VaultError } from "../src/http.ts"
import { sealToVault } from "./l2-helpers.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"

const PROJECT = { kind: "project" as const, project: "prj_a" }
const switchedOff = (ctx: VaultContext): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, BROWSER_FILL: "off" } })

async function machineAsks(ctx: VaultContext, slug: string, kind: "password-login" | "api-key" = "password-login") {
  return createWorkspaceIntake(ctx, devicePrincipal(), { kind, slug, reason: "test", binding: { hosts: ["github.com"] }, home: "project", project: "prj_a" }, await deviceInvocation(ctx)).intake
}

// The person's submission, signed as sent unless `signed` says otherwise.
async function submit(ctx: VaultContext, intake: string, slug: string, extra: Record<string, unknown> = {}, opts: { signed?: Record<string, unknown>; home?: unknown; kind?: "password-login" | "api-key"; role?: string } = {}) {
  const secret = opts.kind === "api-key" ? "key" : "password"
  const req = { slug, home: opts.home ?? PROJECT, binding: { hosts: ["github.com"] }, publicFields: opts.kind === "api-key" ? {} : { url: "https://github.com/login", username: "alex@example.com" }, tags: [], sealed: { [secret]: await sealToVault("hunter2-never-shown", `intake/${intake}/${secret}`) }, ...extra }
  const digest = await stepUpDigest(opts.signed !== undefined ? { ...req, ...opts.signed } : req)
  const role = opts.role ?? "member"
  return submitWorkspaceIntake(ctx, memberPrincipal(ctx, role), { intake, ...req }, memberInvocation(ctx, role, { type: "intake.submit", intake, digest }))
}

async function refusal(run: () => Promise<unknown>) {
  try { await run() } catch (error) { return error instanceof VaultError ? error.toJSON() : error }
  return null
}

const requestStatus = (ctx: VaultContext, intake: string) => ctx.sql.exec<{ status: string }>("SELECT status FROM workspace_credential_requests WHERE id=?", intake).toArray()[0]?.status

describe("the intake's fill choice", () => {
  it("stores fill only when the person's signed submission carries it; a machine cannot name it, and without it the kind's default is stored", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const invocation = await deviceInvocation(ctx)
      expect(await refusal(async () => createWorkspaceIntake(ctx, devicePrincipal(), { kind: "password-login", slug: "machine-fill", reason: "test", binding: { hosts: ["github.com"] }, home: "project", project: "prj_a", ceiling: "fill" }, invocation))).toMatchObject({ error: "bad_request" })
      await submit(ctx, await machineAsks(ctx, "plain-login"), "plain-login")
      expect(checkedCredential(ctx, "plain-login")?.ceiling).toBe("relay")
      await submit(ctx, await machineAsks(ctx, "typed-login"), "typed-login", { ceiling: "fill" })
      expect(checkedCredential(ctx, "typed-login")?.ceiling).toBe("fill")
    })
  })

  it("refuses a submission whose ceiling differs from the one the passkey signed, storing nothing", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const intake = await machineAsks(ctx, "unsigned-fill")
      expect(await refusal(() => submit(ctx, intake, "unsigned-fill", { ceiling: "fill" }, { signed: { ceiling: undefined } }))).toEqual({ error: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      expect(checkedCredential(ctx, "unsigned-fill")).toBeNull()
      expect(requestStatus(ctx, intake)).toBe("open")
    })
  })

  it("parses a body without a ceiling to exactly today's fields, so its digest is unchanged", async () => {
    const body = { slug: "a-login", binding: { hosts: ["github.com"] }, publicFields: { url: "https://github.com" }, sealed: {}, tags: ["b", "a"], home: PROJECT }
    const parsed = IntakeSubmission.extend({ home: CredentialHomeSchema }).parse(body)
    expect(Object.keys(parsed).sort()).toEqual(["binding", "home", "publicFields", "sealed", "slug", "tags"])
    expect(await stepUpDigest({ ...parsed, tags: [...parsed.tags].sort() })).toBe(await stepUpDigest({ slug: "a-login", binding: { hosts: ["github.com"] }, publicFields: { url: "https://github.com" }, sealed: {}, tags: ["a", "b"], home: PROJECT }))
    expect(() => IntakeSubmission.parse({ ...body, ceiling: "mint" })).toThrowError()
  })

  it("refuses fill on a rotation, another kind, with the switch off and in a managed workspace, before anything is stored", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await submit(ctx, await machineAsks(ctx, "rotated-login"), "rotated-login")
      const rotation = await machineAsks(ctx, "rotated-login")
      const version = checkedCredential(ctx, "rotated-login")?.version
      const cases: [string, () => Promise<unknown>, unknown][] = [
        [rotation, () => submit(ctx, rotation, "rotated-login", { ceiling: "fill", publicFields: {} }, { role: "owner" }), { error: "bad_request", message: "A rotation keeps the credential's ceiling." }],
      ]
      const key = await machineAsks(ctx, "typed-key", "api-key")
      cases.push([key, () => submit(ctx, key, "typed-key", { ceiling: "fill" }, { kind: "api-key" }), { error: "bad_request", message: "Only a website or app login can be typed into web pages." }])
      const off = await machineAsks(ctx, "switched-off")
      cases.push([off, () => submit(switchedOff(ctx), off, "switched-off", { ceiling: "fill" }), { error: "mode_refused", message: "Typing into web pages is not available yet." }])
      const managed = await machineAsks(ctx, "managed-login")
      cases.push([managed, async () => { setSetting(ctx, "managed", { platform: "plt_fixture", subject: "sub_fixture", member: "mem_owner", createdAt: ctx.now() }); return submit(ctx, managed, "managed-login", { ceiling: "fill" }) }, { error: "forbidden", message: "A managed workspace's platform cannot decide fills yet, so typing into web pages is not available here." }])
      for (const [intake, run, expected] of cases) {
        expect(await refusal(run)).toEqual(expected)
        expect(requestStatus(ctx, intake)).toBe("open")
      }
      expect(checkedCredential(ctx, "rotated-login")?.version).toBe(version)
      expect(checkedCredential(ctx, "rotated-login")?.ceiling).toBe("relay")
      for (const slug of ["typed-key", "switched-off", "managed-login"]) expect(checkedCredential(ctx, slug)).toBeNull()
    })
  })

  it("keeps a plain intake's audit row as it was, naming no ceiling", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await submit(ctx, await machineAsks(ctx, "plain-audited"), "plain-audited")
      const row = ctx.sql.exec<{ detail: string; target: string }>("SELECT target,detail FROM audit WHERE action='intake.complete' ORDER BY seq DESC LIMIT 1").toArray()[0]!
      expect(row.target).toBe("plain-audited")
      expect(JSON.parse(row.detail)).toEqual({ item: checkedCredential(ctx, "plain-audited")!.id, outcome: "allowed", run: null })
    })
  })

  it("names the ceiling stored in the intake's audit row, with no value, and keeps a private credential's row as it was", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await submit(ctx, await machineAsks(ctx, "audited-login"), "audited-login", { ceiling: "fill" })
      const row = ctx.sql.exec<{ detail: string; target: string }>("SELECT target,detail FROM audit WHERE action='intake.complete' ORDER BY seq DESC LIMIT 1").toArray()[0]!
      expect(row.target).toBe("audited-login")
      expect(JSON.parse(row.detail)).toMatchObject({ ceiling: "fill", outcome: "allowed" })
      expect(row.detail).not.toContain("hunter2")
      const before = ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action='intake.complete'").toArray()[0]!.n
      await submit(ctx, await machineAsks(ctx, "own-login"), "own-login", { ceiling: "fill" }, { home: { kind: "member", member: "mem_member" } })
      expect(checkedCredential(ctx, "own-login")?.ceiling).toBe("fill")
      const rows = ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='intake.complete' ORDER BY seq").toArray().slice(before)
      expect(rows).toHaveLength(1)
      const event = PrivateEventSchema.parse(JSON.parse(rows[0]!.detail))
      expect(rows[0]!.detail).toBe(canonicalJson(event))
      expect(rows[0]!.detail).not.toContain("fill")
    })
  })
})
