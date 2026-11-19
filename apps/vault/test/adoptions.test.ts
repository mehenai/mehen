// The adoptions area (`mehen adopt`) through its operations: who may start,
// fill, read and approve a batch, what each upload refuses, that nothing is
// kept in the clear, and that approval stores exactly what the passkey signed.
import { describe, expect, it } from "vitest"
import { ADOPTION_LIMITS, LEASE_ONLY_HOST, leaseOnlyBinding, adoptionDigest, adoptionRepoints, adoptionSealContext, importSealPublicKey, seal, type AdoptionCreated, type AdoptionDecisionInput, type AdoptionItemUploadInput, type AdoptionStatus, type AdoptionUploaded, type CredentialHome, type WorkspaceAdoptionView, type WorkspacePendingAsk } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { sealPublicJwk } from "../src/seal-key.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { adoptionsArea, workspaceAdoptionOps } from "../src/vault/areas/adoptions.ts"
import { checkedCredential, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { createWorkspaceIntake } from "../src/vault/areas/intake-workspace.ts"
import { workspacePending } from "../src/vault/areas/pending-workspace.ts"
import { workspaceMemberOps } from "../src/vault/areas/workspace-members.ts"
import { accessChanged, openAskCount, runOffboardingHooks, setSetting, type WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"

const SENTINEL = "sk-proj-adopt-sentinel-0123456789abcdefghij"

type Op = keyof typeof workspaceAdoptionOps
async function call<T>(ctx: VaultContext, op: Op, input: unknown, invocation: WorkspaceInvocationContext, p = invocation.auth.kind === "device" ? devicePrincipal(deviceOf(invocation)) : memberPrincipal(ctx, roleOf(invocation))): Promise<T> {
  return await workspaceAdoptionOps[op].handler(ctx, p, input, invocation) as T
}
function deviceOf(invocation: WorkspaceInvocationContext): string { return JSON.parse(atob((invocation.auth as { proof: string }).proof.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))).dev }
function roleOf(invocation: WorkspaceInvocationContext): string { return (invocation.auth as { account: string }).account.slice(4) }
async function refused(promise: Promise<unknown> | (() => unknown)): Promise<{ error: string; message: string; refused?: unknown }> {
  try { await (typeof promise === "function" ? promise() : promise) } catch (error) { if (error instanceof VaultError) return error.toJSON() as { error: string; message: string }; throw error }
  throw new Error("accepted")
}

async function box(ctx: VaultContext, adoption: string, ref: string, field: string, value: string) {
  const { jwk } = await sealPublicJwk(ctx.env)
  return seal(await importSealPublicKey(jwk), value, adoptionSealContext(adoption, ref, field))
}
async function item(ctx: VaultContext, adoption: string, ref: string, slug: string, value = SENTINEL, extra: Partial<AdoptionItemUploadInput> = {}): Promise<AdoptionItemUploadInput> {
  return { ref, slug, kind: "api-key", provider: "openai", binding: null, injection: null, home: { kind: "workspace" }, tags: ["adopted"], publicFields: {}, sealed: { key: await box(ctx, adoption, ref, "key", value) }, sources: [{ path: "/home/alex/app/.env", variable: "OPENAI_API_KEY", stale: [] }], repo: { remote: "github.com/alex/app", env: "dev" }, ...extra }
}
async function start(ctx: VaultContext, device = "dev_owner"): Promise<AdoptionCreated> {
  return call<AdoptionCreated>(ctx, "adoption.create", { machine: "office", expectedItems: 2 }, await deviceInvocation(ctx, device))
}
async function upload(ctx: VaultContext, adoption: string, items: AdoptionItemUploadInput[], device = "dev_owner"): Promise<AdoptionUploaded> {
  return call<AdoptionUploaded>(ctx, "adoption.upload", { adoption, items }, await deviceInvocation(ctx, device))
}
function view(ctx: VaultContext, adoption: string, role = "owner"): Promise<WorkspaceAdoptionView> {
  return call<WorkspaceAdoptionView>(ctx, "adoption.view", { adoption }, memberInvocation(ctx, role))
}
function decide(v: WorkspaceAdoptionView, include: (ref: string) => boolean = () => true, home: (ref: string) => CredentialHome = () => ({ kind: "workspace" })): AdoptionDecisionInput[] {
  return v.items.map(i => ({ ref: i.ref, include: include(i.ref), home: home(i.ref) }))
}
async function approve(ctx: VaultContext, v: WorkspaceAdoptionView, decisions: AdoptionDecisionInput[], role = "owner", digest?: string): Promise<AdoptionStatus> {
  const action = { type: "adoption.approve" as const, adoption: v.adoption, digest: digest ?? await adoptionDigest(v.adoption, v.items, decisions), repoints: adoptionRepoints(decisions) }
  return call<AdoptionStatus>(ctx, "adoption.approve", { adoption: v.adoption, decisions }, memberInvocation(ctx, role, action))
}
function tableText(ctx: VaultContext): string {
  return ["adoption_batches", "adoption_items", "adoption_secrets", "adoption_machines", "audit"].map(t => JSON.stringify(ctx.sql.exec(`SELECT * FROM ${t}`).toArray(), (_k, v) => v instanceof ArrayBuffer ? new TextDecoder().decode(v) : v)).join("\n")
}
function storedFingerprint(ctx: VaultContext, item: string): string | undefined {
  return ctx.sql.exec<{ fingerprint: string }>("SELECT fingerprint FROM item_secrets WHERE item=? AND name='key'", item).toArray()[0]?.fingerprint
}
function misses(ctx: VaultContext, subject: string): number {
  return ctx.sql.exec<{ count: number }>("SELECT count FROM name_miss_buckets WHERE subject=?", subject).toArray()[0]?.count ?? 0
}

describe("adoptions", () => {
  it("create: who may adopt", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const created = await start(ctx)
      expect(created.adoption).toMatch(/^adp_/)
      expect(created.url).toBe(`https://vault.test/w/work/b/${created.adoption}`)
      expect(created.limits).toEqual(ADOPTION_LIMITS)
      expect(created.sealKey).toEqual(await sealPublicJwk(ctx.env))
      const invocation = await deviceInvocation(ctx, "dev_owner")
      expect(await refused(call(ctx, "adoption.create", { machine: "office", expectedItems: 1 }, invocation, { kind: "device", deviceId: "dev_owner", workload: "wkl_task" }))).toMatchObject({ error: "forbidden", message: expect.stringContaining("A workload cannot adopt") })
      expect(await refused(start(ctx, "dev_guest"))).toMatchObject({ error: "forbidden", message: "A guest's machine cannot adopt secrets." })
      expect(await refused(call(ctx, "adoption.create", { machine: "office", expectedItems: 1 }, memberInvocation(ctx)))).toMatchObject({ error: "forbidden" })
      await start(ctx); await start(ctx)
      expect(await refused(start(ctx))).toMatchObject({ error: "rate_limited", message: `There are already ${ADOPTION_LIMITS.maxOpenPerMember} open adoption batches.` })
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(await refused(start(ctx, "dev_member"))).toMatchObject({ error: "forbidden", message: expect.stringContaining("managed workspace") })
    })
  })

  it("upload: per item refusals, never echoing a value", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      const other = await start(ctx)
      const wrongRef = await item(ctx, adoption, "a001", "wrong-ref")
      wrongRef.sealed = { key: await box(ctx, adoption, "a999", "key", SENTINEL) }
      const wrongBatch = await item(ctx, adoption, "a002", "wrong-batch")
      wrongBatch.sealed = { key: await box(ctx, other.adoption, "a002", "key", SENTINEL) }
      const unknownField = await item(ctx, adoption, "a003", "unknown-field")
      unknownField.sealed = { ...unknownField.sealed, password: await box(ctx, adoption, "a003", "password", SENTINEL) }
      const missing = await item(ctx, adoption, "a004", "missing-field", SENTINEL, { sealed: {} })
      const badHost = await item(ctx, adoption, "a005", "bad-host", SENTINEL, { provider: null, binding: { hosts: ["not a host"] } })
      const secretPublic = await item(ctx, adoption, "a006", "secret-public", SENTINEL, { kind: "basic-auth", provider: null, binding: { hosts: ["api.example.com"] }, publicFields: { username: SENTINEL }, sealed: { password: await box(ctx, adoption, "a006", "password", SENTINEL) } })
      const mismatch = await item(ctx, adoption, "a007", "mismatch", SENTINEL, { kind: "bearer-token" })
      const unknownTemplate = await item(ctx, adoption, "a008", "unknown-template", SENTINEL, { provider: "no-such-template" })
      const good = await item(ctx, adoption, "a009", "good-one")
      const result = await upload(ctx, adoption, [wrongRef, wrongBatch, unknownField, missing, badHost, secretPublic, mismatch, unknownTemplate, good])
      expect(result.accepted).toEqual(["a009"])
      expect(Object.fromEntries(result.refused.map(r => [r.ref, r.reason]))).toEqual({
        a001: "The sealed field does not belong to this adoption.",
        a002: "The sealed field does not belong to this adoption.",
        a003: "\"password\" is not a secret field of a API key.",
        a004: "API key needs \"Key\".",
        a005: expect.stringContaining("is not a host the vault can bind to"),
        a006: "\"username\" looks like a secret; send it sealed, as a secret field.",
        a007: "The credential kind does not match its template.",
        a008: "Unknown credential template.",
      })
      expect(JSON.stringify(result)).not.toContain(SENTINEL)
      // More than 16 tags fails the whole chunk's shape.
      expect(await refused(upload(ctx, adoption, [{ ...good, ref: "a010", slug: "many-tags", tags: Array.from({ length: 17 }, (_, i) => `t${i}`) }]))).toMatchObject({ error: "bad_request" })
      // Kept refusals are listed by status; the retried good row is accepted again, not doubled.
      expect((await upload(ctx, adoption, [good])).accepted).toEqual(["a009"])
      // The same ref with the same boxes but other contents is not a retry.
      for (const changed of [{ ...good, tags: ["changed"] }, { ...good, slug: "other-slug" }, { ...good, home: { kind: "member" as const, member: "mem_owner" } }]) expect(await upload(ctx, adoption, [changed])).toEqual({ adoption, accepted: [], refused: [{ ref: "a009", reason: "This row is already in the batch with different contents." }] })
      expect(ctx.sql.exec("SELECT slug,tags,home FROM adoption_items WHERE ref='a009'").toArray()).toEqual([{ slug: "good-one", tags: "[\"adopted\"]", home: "{\"kind\":\"workspace\"}" }])
      const status = await call<AdoptionStatus>(ctx, "adoption.status", { adoption }, await deviceInvocation(ctx, "dev_owner"))
      expect(status.refused?.map(r => r.ref)).toEqual(["a001", "a002", "a003", "a004", "a005", "a006", "a007", "a008"])
      expect(status.machines).toEqual([{ device: "dev_owner", name: "office", items: 1 }])
    })
  })

  it("upload: a custom credential with no binding and no injection is stored lease-only", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      const jwt = await item(ctx, adoption, "a001", "jwt-secret", SENTINEL, { kind: "generic", provider: null, sealed: { value: await box(ctx, adoption, "a001", "value", SENTINEL) }, sources: [{ path: "/home/alex/app/.env", variable: "JWT_SECRET", stale: [] }] })
      const db = await item(ctx, adoption, "a002", "database-url", SENTINEL, { kind: "database-url", provider: null, sealed: { url: await box(ctx, adoption, "a002", "url", "postgres://app:pw@db.internal/app") }, sources: [{ path: "/home/alex/app/.env", variable: "DATABASE_URL", stale: [] }] })
      const injected = await item(ctx, adoption, "a003", "injected-no-host", SENTINEL, { provider: null, injection: { in: "header", name: "X-Api-Key", format: "{key}" } })
      const reservedInjected = await item(ctx, adoption, "a004", "injected-reserved", SENTINEL, { provider: null, binding: leaseOnlyBinding(), injection: { in: "header", name: "X-Api-Key", format: "{key}" } })
      const result = await upload(ctx, adoption, [jwt, db, injected, reservedInjected])
      expect(result.accepted).toEqual(["a001", "a002"])
      expect(result.refused).toEqual(["a003", "a004"].map(ref => ({ ref, reason: "A custom credential sent with an injection needs a binding with the hosts it goes to." })))
      const v = await view(ctx, adoption)
      expect(v.items.map(i => [i.ref, i.binding])).toEqual([["a001", { value: { hosts: [LEASE_ONLY_HOST] }, verified: false }], ["a002", { value: { hosts: [LEASE_ONLY_HOST] }, verified: false }]])
      await approve(ctx, v, decide(v))
      for (const slug of ["jwt-secret", "database-url"]) expect(checkedCredential(ctx, slug)).toMatchObject({ binding: { hosts: [LEASE_ONLY_HOST] }, injection: null })
    })
  })

  it("upload: a kind the relay injects needs hosts, and a store-only kind with no hosts keeps its ceiling", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      const bearer = await item(ctx, adoption, "a001", "bearer-no-host", SENTINEL, { kind: "bearer-token", provider: null, sealed: { token: await box(ctx, adoption, "a001", "token", SENTINEL) } })
      const reserved = await item(ctx, adoption, "a002", "api-key-reserved", SENTINEL, { provider: null, binding: leaseOnlyBinding() })
      const ssh = await item(ctx, adoption, "a003", "deploy-ssh", SENTINEL, { kind: "ssh-key", provider: null, sealed: { private_key: await box(ctx, adoption, "a003", "private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----") } })
      const hmac = await item(ctx, adoption, "a004", "webhook-signing", SENTINEL, { kind: "hmac-key", provider: null })
      const result = await upload(ctx, adoption, [bearer, reserved, ssh, hmac])
      expect(result.refused).toEqual([
        { ref: "a001", reason: "A bearer-token credential is sent to a service: name the hosts it may go to with --host." },
        { ref: "a002", reason: "An api-key credential is sent to a service: name the hosts it may go to with --host." },
      ])
      expect(result.accepted).toEqual(["a003", "a004"])
      const v = await view(ctx, adoption)
      await approve(ctx, v, decide(v))
      expect(checkedCredential(ctx, "deploy-ssh")).toMatchObject({ kind: "ssh-key", ceiling: "sign", binding: { hosts: [LEASE_ONLY_HOST] }, injection: null })
      expect(checkedCredential(ctx, "webhook-signing")).toMatchObject({ kind: "hmac-key", ceiling: "sign", binding: { hosts: [LEASE_ONLY_HOST] }, injection: null })
    })
  })

  it("upload: refuses a proposed injection on a custom credential whose kind the relay never puts into a request, as intake does", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      const hosts = { hosts: ["api.example.com"] }
      const injection = { in: "header" as const, name: "X-Api-Key", format: "{key}" }
      const hmac = await item(ctx, adoption, "a001", "webhook-signing", SENTINEL, { kind: "hmac-key", provider: null, binding: hosts, injection })
      const plainHmac = await item(ctx, adoption, "a002", "webhook-plain", SENTINEL, { kind: "hmac-key", provider: null, binding: hosts })
      // Without hosts too, the injection is the reason given first, as intake gives it.
      const hostlessHmac = await item(ctx, adoption, "a003", "webhook-hostless", SENTINEL, { kind: "hmac-key", provider: null, binding: null, injection })
      const result = await upload(ctx, adoption, [hmac, plainHmac, hostlessHmac])
      const reason = "The relay never puts a Signing secret (HMAC) into a request, so it takes no injection. Leave it out."
      expect(result.refused).toEqual([{ ref: "a001", reason }, { ref: "a003", reason }])
      expect(result.accepted).toEqual(["a002"])
    })
  })

  it("upload: names and the name budget", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "taken-item")
      createWorkspaceIntake(ctx, memberPrincipal(ctx), { provider: "openai", slug: "held-by-intake", home: "workspace" }, memberInvocation(ctx))
      const first = await start(ctx)
      expect((await upload(ctx, first.adoption, [await item(ctx, first.adoption, "a001", "held-by-batch")])).accepted).toEqual(["a001"])
      const { adoption } = await start(ctx)
      const before = misses(ctx, "device:dev_owner")
      const result = await upload(ctx, adoption, [await item(ctx, adoption, "a001", "taken-item"), await item(ctx, adoption, "a002", "held-by-intake"), await item(ctx, adoption, "a003", "held-by-batch"), await item(ctx, adoption, "a004", "twice"), await item(ctx, adoption, "a005", "twice")])
      expect(result.accepted).toEqual(["a004"])
      expect(result.refused).toEqual(["a001", "a002", "a003", "a005"].map(ref => ({ ref, reason: "name not available" })))
      expect(misses(ctx, "device:dev_owner")).toBe(before + 4)
      // A staged name blocks a new intake and a new item.
      expect(await refused(() => createWorkspaceIntake(ctx, memberPrincipal(ctx), { provider: "openai", slug: "held-by-batch", home: "workspace" }, memberInvocation(ctx)))).toEqual({ error: "conflict", message: "name not available" })
      // The miss that spends the budget refuses the rest of the chunk; a chunk
      // that starts with it spent is refused whole.
      ctx.sql.exec("UPDATE name_miss_buckets SET count=19")
      const rest = await upload(ctx, adoption, [await item(ctx, adoption, "a006", "taken-item"), await item(ctx, adoption, "a007", "budget-two")])
      expect(rest.accepted).toEqual([])
      expect(rest.refused).toEqual([{ ref: "a006", reason: "name not available" }, { ref: "a007", reason: expect.stringMatching(/^Too many unavailable names; try again later\. Retry after \d+ seconds\.$/) }])
      expect(await refused(upload(ctx, adoption, [await item(ctx, adoption, "a008", "budget-three")]))).toMatchObject({ error: "rate_limited", message: "Too many unavailable names; try again later.", retryAfter: expect.any(Number) })
    })
  })

  it("upload: nothing in the clear at rest", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      const secretPublic = await item(ctx, adoption, "a003", "secret-public", SENTINEL, { kind: "basic-auth", provider: null, binding: { hosts: ["api.example.com"] }, publicFields: { username: SENTINEL }, sealed: { password: await box(ctx, adoption, "a003", "password", SENTINEL) } })
      expect((await upload(ctx, adoption, [await item(ctx, adoption, "a001", "clear-one"), await item(ctx, adoption, "a002", "clear-two", SENTINEL), secretPublic])).refused.map(r => r.ref)).toEqual(["a003"])
      expect(tableText(ctx)).not.toContain(SENTINEL)
      expect(tableText(ctx)).not.toContain("adopt-sentinel")
      expect(ctx.sql.exec("SELECT public_fields,sources FROM adoption_items WHERE ref='a003'").toArray()).toEqual([{ public_fields: "{}", sources: "[]" }])
      const rows = ctx.sql.exec<{ fingerprint: string; dup_tag: string; root_version: number; length: number; prefix: string }>("SELECT * FROM adoption_secrets").toArray()
      expect(rows).toHaveLength(2)
      for (const row of rows) {
        expect(row.dup_tag).not.toBe(row.fingerprint)
        expect(row.length).toBe(SENTINEL.length)
        expect(row.prefix).toBe("sk-proj-")
        expect(row.root_version).toBe(ctx.rootVersion)
      }
      expect(rows[0]!.dup_tag).toBe(rows[1]!.dup_tag)
      expect(rows[0]!.fingerprint).not.toBe(rows[1]!.fingerprint)
      expect(JSON.stringify(await view(ctx, adoption))).not.toContain(rows[0]!.dup_tag)
      // Public fields a refused row still carries are cleared when its batch is approved or ends.
      const carry = (id: string) => ctx.sql.exec("UPDATE adoption_items SET public_fields=? WHERE adoption=? AND status='refused'", JSON.stringify({ username: SENTINEL }), id)
      carry(adoption)
      const v = await view(ctx, adoption)
      await approve(ctx, v, decide(v))
      expect(tableText(ctx)).not.toContain(SENTINEL)
      const other = await start(ctx)
      await upload(ctx, other.adoption, [{ ...secretPublic, sealed: { password: await box(ctx, other.adoption, "a003", "password", SENTINEL) } }])
      carry(other.adoption)
      await call(ctx, "adoption.cancel", { adoption: other.adoption }, await deviceInvocation(ctx, "dev_owner"))
      expect(tableText(ctx)).not.toContain(SENTINEL)
    })
  })

  it("view: duplicates only inside the batch, only for the requester", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const stored = await seedCredential(ctx, "already-stored")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "dup-one"), await item(ctx, adoption, "a002", "dup-two"), await item(ctx, adoption, "a003", "unique", "test-secret-never-returned")])
      const v = await view(ctx, adoption)
      expect(v.items.map(i => [i.ref, i.sameValueAs])).toEqual([["a001", ["a002"]], ["a002", ["a001"]], ["a003", []]])
      expect(v.items[2]!.secrets[0]!.fingerprint).not.toBe(storedFingerprint(ctx, stored.id))
      expect(v.items[0]).toMatchObject({ provider: "openai", providerName: "OpenAI API key", binding: { verified: true }, home: { kind: "workspace" }, problem: null, sources: [{ machine: "office", path: "/home/alex/app/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [] }] })
      expect(v.items[0]!.homesAllowed).toEqual(expect.arrayContaining([{ kind: "workspace" }, { kind: "member", member: "mem_owner" }]))
      expect(v.requestedBy).toEqual({ device: "dev_owner", deviceName: "office", session: null })
      for (const role of ["admin", "member", "guest"]) expect(await refused(view(ctx, adoption, role))).toEqual({ error: "not_found", message: "No such adoption." })
    })
  })

  it("approve: stores exactly what was signed, audited per item without values", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "adopt-workspace"), await item(ctx, adoption, "a002", "adopt-private"), await item(ctx, adoption, "a003", "adopt-left-out")])
      const v = await view(ctx, adoption)
      const decisions = decide(v, ref => ref !== "a003", ref => ref === "a002" ? { kind: "member", member: "mem_owner" } : { kind: "workspace" })
      const before = ctx.sql.exec<{ seq: number }>("SELECT COALESCE(MAX(seq),0) AS seq FROM audit").toArray()[0]!.seq
      const status = await approve(ctx, v, decisions)
      expect(status).toMatchObject({ status: "approved", created: [{ ref: "a001", slug: "adopt-workspace" }, { ref: "a002", slug: "adopt-private" }], refused: [{ ref: "a003", reason: "Left out at review." }] })
      const workspace = checkedCredential(ctx, "adopt-workspace")!, personal = checkedCredential(ctx, "adopt-private")!
      expect(workspace.home).toEqual({ kind: "workspace" })
      expect(personal.home).toEqual({ kind: "member", member: "mem_owner" })
      expect(workspace.tags).toEqual(["adopted"])
      expect(workspace.id).toBe(ctx.sql.exec<{ item_id: string }>("SELECT item_id FROM adoption_items WHERE ref='a001'").toArray()[0]!.item_id)
      expect(storedFingerprint(ctx, workspace.id)).toBe(v.items[0]!.secrets[0]!.fingerprint)
      expect(checkedCredential(ctx, "adopt-left-out")).toBeNull()
      expect(ctx.sql.exec("SELECT * FROM adoption_secrets").toArray()).toEqual([])
      const audit = ctx.sql.exec<{ action: string; target: string | null; detail: string }>("SELECT action,target,detail FROM audit WHERE seq>? ORDER BY seq", before).toArray()
      expect(audit.map(a => a.action)).toEqual(["item.create", "adoption.item", "item.create", "adoption.item", "adoption.approve"])
      expect(JSON.parse(audit.at(-1)!.detail)).toMatchObject({ created: 2, excluded: 1 })
      expect(tableText(ctx)).not.toContain(SENTINEL)
      // The same decisions again answer what was stored; others are refused.
      expect(await approve(ctx, v, decisions)).toEqual(status)
      expect(await refused(approve(ctx, v, decide(v)))).toEqual({ error: "conflict", message: "This adoption batch is no longer open." })
      expect(await call<AdoptionStatus>(ctx, "adoption.status", { adoption }, await deviceInvocation(ctx, "dev_owner"))).toEqual(status)
    })
  })

  it("approve: a late upload or a stale digest invalidates the review", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "late-one")])
      const v = await view(ctx, adoption)
      const digest = await adoptionDigest(adoption, v.items, decide(v))
      await upload(ctx, adoption, [await item(ctx, adoption, "a002", "late-two")])
      const fresh = await view(ctx, adoption)
      expect(await refused(approve(ctx, fresh, decide(fresh), "owner", digest))).toEqual({ error: "conflict", message: "This batch changed; reload it." })
      // A decision list for the old view misses the new row.
      expect(await refused(approve(ctx, v, decide(v)))).toMatchObject({ error: "bad_request", message: "Every row in the batch needs exactly one decision." })
      // A tampered row: the signed home is not the decided one.
      const signed = await adoptionDigest(adoption, fresh.items, decide(fresh))
      expect(await refused(approve(ctx, fresh, decide(fresh, () => true, () => ({ kind: "member", member: "mem_owner" })), "owner", signed))).toEqual({ error: "conflict", message: "This batch changed; reload it." })
      // Without the passkey over this exact action, nothing is stored.
      expect(await refused(call(ctx, "adoption.approve", { adoption, decisions: decide(fresh) }, memberInvocation(ctx)))).toEqual({ error: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      expect(checkedCredential(ctx, "late-one")).toBeNull()
      expect((await approve(ctx, fresh, decide(fresh))).status).toBe("approved")
    })
  })

  it("approve: all or nothing with reasons", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "whole-one"), await item(ctx, adoption, "a002", "whole-two"), await item(ctx, adoption, "a003", "whole-three")])
      await seedCredential(ctx, "whole-three")
      const v = await view(ctx, adoption)
      expect(v.items.find(i => i.ref === "a003")?.problem).toBe("This name is no longer available.")
      const decisions = decide(v, () => true, ref => ref === "a002" ? { kind: "member", member: "mem_admin" } : { kind: "workspace" })
      const error = await refused(approve(ctx, v, decisions))
      expect(error).toMatchObject({ error: "conflict", message: "2 credentials in this batch cannot be stored, so nothing was stored.", refused: [{ ref: "a002", reason: "You cannot add credentials to this home; choose another." }, { ref: "a003", reason: "This name is no longer available." }] })
      expect(checkedCredential(ctx, "whole-one")).toBeNull()
      expect(ctx.sql.exec<{ action: string }>("SELECT action FROM audit ORDER BY seq DESC LIMIT 1").toArray()[0]!.action).toBe("adoption.refused")
      expect(ctx.sql.exec("SELECT * FROM adoption_secrets").toArray()).toHaveLength(3)
      const status = await approve(ctx, v, decide(v, ref => ref !== "a003"))
      expect(status.created?.map(c => c.slug)).toEqual(["whole-one", "whole-two"])
    })
  })

  it("approve: who may approve", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx, "dev_member")
      expect(await upload(ctx, adoption, [await item(ctx, adoption, "a001", "member-batch", SENTINEL, { home: { kind: "project", project: "prj_a" } })], "dev_member")).toMatchObject({ accepted: ["a001"] })
      const v = await view(ctx, adoption, "member")
      const decisions = decide(v, () => true, () => ({ kind: "project", project: "prj_a" }))
      for (const role of ["owner", "admin", "guest"]) expect(await refused(approve(ctx, v, decisions, role))).toEqual({ error: "not_found", message: "No such adoption." })
      const digest = await adoptionDigest(adoption, v.items, decisions)
      expect(await refused(call(ctx, "adoption.approve", { adoption, decisions }, await deviceInvocation(ctx, "dev_member")))).toMatchObject({ error: "forbidden" })
      // The member may not store into the workspace home.
      expect(await refused(approve(ctx, v, decide(v)))).toMatchObject({ error: "not_found" })
      expect(await refused(approve(ctx, v, decide(v), "member"))).toMatchObject({ error: "conflict", refused: [{ ref: "a001", reason: "You cannot add credentials to this home; choose another." }] })
      expect((await approve(ctx, v, decisions, "member", digest)).status).toBe("approved")
      // A team machine's batch is decided by an owner or admin.
      ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.level','edit') WHERE id='shr_service'")
      const team = await start(ctx, "dev_service")
      expect(await upload(ctx, team.adoption, [await item(ctx, team.adoption, "a001", "team-batch", SENTINEL, { home: { kind: "project", project: "prj_a" } })], "dev_service")).toMatchObject({ accepted: ["a001"] })
      expect(await refused(view(ctx, team.adoption, "member"))).toEqual({ error: "not_found", message: "No such adoption." })
      const tv = await view(ctx, team.adoption, "admin")
      expect((await approve(ctx, tv, decide(tv, () => true, () => ({ kind: "project", project: "prj_a" })), "admin")).status).toBe("approved")
    })
  })

  it("a batch is one open ask, listed as pending with its count", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption, expiresAt } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "pending-one"), await item(ctx, adoption, "a002", "pending-two")])
      expect(openAskCount(ctx, "dev_owner")).toBe(1)
      const asks = workspacePending(ctx, memberPrincipal(ctx), memberInvocation(ctx)).filter(a => a.view === "detail" && a.detail.kind === "adoption") as Extract<WorkspacePendingAsk, { view: "detail" }>[]
      expect(asks).toHaveLength(1)
      expect(asks[0]!.detail).toMatchObject({ kind: "adoption", id: adoption, items: 2, title: "Adopt 2 credentials", url: `https://vault.test/w/work/b/${adoption}`, expiresAt, requestedBy: { device: "dev_owner", deviceName: "office", session: null } })
      expect(workspacePending(ctx, devicePrincipal("dev_owner"), await deviceInvocation(ctx, "dev_owner")).some(a => a.view === "detail" && a.detail.id === adoption)).toBe(true)
      for (const role of ["admin", "member"]) expect(workspacePending(ctx, memberPrincipal(ctx, role), memberInvocation(ctx, role)).some(a => a.view === "detail" && a.detail.id === adoption)).toBe(false)
      expect(workspacePending(ctx, devicePrincipal("dev_member"), await deviceInvocation(ctx, "dev_member")).some(a => a.view === "detail" && a.detail.id === adoption)).toBe(false)
    })
  })

  it("cancel, revoke and offboarding end the batch and purge its staged secrets", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const staged = async (device: string) => { const { adoption } = await start(ctx, device); await upload(ctx, adoption, [await item(ctx, adoption, "a001", `end-${adoption.slice(-6).toLowerCase()}`)], device); return adoption }
      const left = (adoption: string) => ctx.sql.exec("SELECT 1 FROM adoption_secrets WHERE adoption=?", adoption).toArray().length
      const status = (adoption: string) => ctx.sql.exec<{ status: string }>("SELECT status FROM adoption_batches WHERE id=?", adoption).toArray()[0]!.status
      const byMachine = await staged("dev_owner")
      expect(await call(ctx, "adoption.cancel", { adoption: byMachine }, await deviceInvocation(ctx, "dev_owner"))).toEqual({})
      expect([status(byMachine), left(byMachine)]).toEqual(["cancelled", 0])
      const byPerson = await staged("dev_owner")
      expect(await refused(call(ctx, "adoption.cancel", { adoption: byPerson }, memberInvocation(ctx, "admin")))).toEqual({ error: "not_found", message: "No such adoption." })
      expect(await refused(call(ctx, "adoption.cancel", { adoption: byPerson }, await deviceInvocation(ctx, "dev_member")))).toEqual({ error: "not_found", message: "No such adoption." })
      await call(ctx, "adoption.cancel", { adoption: byPerson }, memberInvocation(ctx))
      expect([status(byPerson), left(byPerson)]).toEqual(["cancelled", 0])
      const revoked = await staged("dev_owner")
      accessChanged(ctx, "mem_owner", "revoke", { device: "dev_owner" })
      expect([status(revoked), left(revoked)]).toEqual(["cancelled", 0])
      const offboarded = await staged("dev_member")
      runOffboardingHooks(ctx, { removal: "rm_1", by: "mem_owner", member: "mem_member", devices: ["dev_member"], privateItems: [], exposures: [], accessRevision: 1 })
      expect([status(offboarded), left(offboarded)]).toEqual(["cancelled", 0])
      expect(ctx.sql.exec<{ actor: string; detail: string }>("SELECT actor,detail FROM audit WHERE action='adoption.cancel' ORDER BY seq").toArray().map(r => [r.actor, JSON.parse(r.detail).reason])).toEqual([["device:dev_owner", "machine"], ["member:mem_owner", "person"], ["system", "device_revoked"], ["system", "member_removed"]])
    })
  })

  it("a member who becomes a guest ends their open batches and uploads no more", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx, "dev_member")
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "demoted-one", SENTINEL, { home: { kind: "project", project: "prj_a" } })], "dev_member")
      const other = await start(ctx, "dev_member")
      // Without the role hook, the upload itself refuses a guest's machine.
      ctx.sql.exec("UPDATE members SET role='guest' WHERE id='mem_member'")
      expect(await refused(upload(ctx, other.adoption, [await item(ctx, other.adoption, "a001", "demoted-two")], "dev_member"))).toMatchObject({ error: "forbidden", message: "A guest's machine cannot adopt secrets." })
      ctx.sql.exec("UPDATE members SET role='member' WHERE id='mem_member'")
      workspaceMemberOps["access.members.role"]!.handler(ctx, memberPrincipal(ctx), { member: "mem_member", role: "guest" }, memberInvocation(ctx, "owner", { type: "member.role", member: "mem_member", before: "member", after: "guest" }))
      expect(ctx.sql.exec<{ id: string; status: string }>("SELECT id,status FROM adoption_batches ORDER BY id").toArray().map(b => b.status)).toEqual(["cancelled", "cancelled"])
      expect(ctx.sql.exec("SELECT * FROM adoption_secrets").toArray()).toEqual([])
      expect(ctx.sql.exec<{ detail: string }>("SELECT detail FROM audit WHERE action='adoption.cancel'").toArray().map(r => JSON.parse(r.detail).reason)).toEqual(["owner_guest", "owner_guest"])
    })
  })

  it("expiry purges staged secrets", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "expiring")])
      await adoptionsArea.alarm!(ctx, adoption)
      expect(ctx.sql.exec<{ status: string }>("SELECT status FROM adoption_batches WHERE id=?", adoption).toArray()[0]!.status).toBe("open")
      ctx.sql.exec("UPDATE adoption_batches SET expires_at=? WHERE id=?", ctx.now() - 1, adoption)
      expect((await call<AdoptionStatus>(ctx, "adoption.status", { adoption }, await deviceInvocation(ctx, "dev_owner"))).status).toBe("expired")
      expect(await refused(upload(ctx, adoption, [await item(ctx, adoption, "a002", "too-late")]))).toEqual({ error: "conflict", message: "This adoption batch is no longer open." })
      await adoptionsArea.alarm!(ctx, adoption)
      expect(ctx.sql.exec<{ status: string }>("SELECT status FROM adoption_batches WHERE id=?", adoption).toArray()[0]!.status).toBe("expired")
      expect(ctx.sql.exec("SELECT * FROM adoption_secrets").toArray()).toEqual([])
      expect(ctx.sql.exec<{ status: string }>("SELECT status FROM adoption_items").toArray()).toEqual([{ status: "expired" }])
      expect(openAskCount(ctx, "dev_owner")).toBe(0)
      // The name is free again.
      expect((await workspaceItemOps["items.list"]?.handler(ctx, memberPrincipal(ctx), {}, memberInvocation(ctx)))).toBeDefined()
      createWorkspaceIntake(ctx, memberPrincipal(ctx), { provider: "openai", slug: "expiring", home: "workspace" }, memberInvocation(ctx))
    })
  })

  it("limits: 500 items, 500 kept refusals, 8 MB staged and 8 machines per batch", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      const fill = (n: number, length: number, status = "staged") => {
        for (let i = 0; i < n; i++) {
          const ref = `z${i.toString(36).padStart(4, "0")}`
          ctx.sql.exec("INSERT INTO adoption_items(adoption,ref,item_id,device,slug,kind,provider,binding,injection,home,tags,public_fields,sources,repo,status,refusal,uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,0)", adoption, ref, `itm_${ref}`, "dev_owner", `filler-${ref}`, "api-key", "openai", "{}", null, "{\"kind\":\"workspace\"}", "[]", "{}", "[]", null, status)
          if (status === "staged") ctx.sql.exec("INSERT INTO adoption_secrets(adoption,ref,field,root_version,wrapped_dek,ciphertext,length,prefix,fingerprint,fp_version,box_digest,dup_tag) VALUES (?,?,'key',1,?,?,?,'','f',1,'b',?)", adoption, ref, new Uint8Array(1), new Uint8Array(1), length, ref)
        }
      }
      fill(ADOPTION_LIMITS.maxItems, 1)
      expect((await upload(ctx, adoption, [await item(ctx, adoption, "a001", "one-too-many")])).refused).toEqual([{ ref: "a001", reason: `This batch is full: at most ${ADOPTION_LIMITS.maxItems} credentials.` }])
      ctx.sql.exec("DELETE FROM adoption_items WHERE adoption=?", adoption); ctx.sql.exec("DELETE FROM adoption_secrets WHERE adoption=?", adoption)
      fill(1, ADOPTION_LIMITS.maxStagedBytes - 5)
      expect((await upload(ctx, adoption, [await item(ctx, adoption, "a002", "too-many-bytes")])).refused).toEqual([{ ref: "a002", reason: `This batch holds as much as it can: at most ${ADOPTION_LIMITS.maxStagedBytes} characters of secrets.` }])
      // Past the cap a refusal is still answered, but no longer kept.
      ctx.sql.exec("DELETE FROM adoption_items WHERE adoption=?", adoption); ctx.sql.exec("DELETE FROM adoption_secrets WHERE adoption=?", adoption)
      fill(ADOPTION_LIMITS.maxItems, 1, "refused")
      expect((await upload(ctx, adoption, [await item(ctx, adoption, "a004", "not-kept", SENTINEL, { provider: "no-such-template" })])).refused).toEqual([{ ref: "a004", reason: "Unknown credential template." }])
      expect(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_items WHERE adoption=?", adoption).toArray()[0]!.count).toBe(ADOPTION_LIMITS.maxItems)
      expect(ctx.sql.exec("SELECT 1 FROM adoption_items WHERE ref='a004'").toArray()).toEqual([])
      for (let i = 1; i < ADOPTION_LIMITS.maxMachines; i++) ctx.sql.exec("INSERT INTO adoption_machines(adoption,device,name) VALUES (?,?,?)", adoption, `dev_other${i}`, `other-${i}`)
      ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) SELECT 'dev_owner2','laptop',backend,jwk,'dev_owner2',scope,created_at,owner_kind,owner_id FROM devices WHERE id='dev_owner'")
      expect(await refused(upload(ctx, adoption, [await item(ctx, adoption, "a003", "ninth-machine")], "dev_owner2"))).toEqual({ error: "conflict", message: `This batch already has ${ADOPTION_LIMITS.maxMachines} machines.` })
    })
  })

  it("limits: calls that interleave are counted again where they write", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const created = await Promise.allSettled(Array.from({ length: ADOPTION_LIMITS.maxOpenPerMember + 1 }, () => start(ctx)))
      expect(created.filter(r => r.status === "fulfilled")).toHaveLength(ADOPTION_LIMITS.maxOpenPerMember)
      expect(created.flatMap(r => r.status === "rejected" ? [(r.reason as VaultError).toJSON()] : [])).toEqual([{ error: "rate_limited", message: `There are already ${ADOPTION_LIMITS.maxOpenPerMember} open adoption batches.`, next: expect.anything() }])
      const adoption = (created.find(r => r.status === "fulfilled") as PromiseFulfilledResult<AdoptionCreated>).value.adoption
      for (const id of ["dev_owner2", "dev_owner3", "dev_owner4"]) ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) SELECT ?,'laptop',backend,jwk,?,scope,created_at,owner_kind,owner_id FROM devices WHERE id='dev_owner'", id, id)
      // Two first chunks from one newly joined machine.
      const [first, second, third, fourth] = [await item(ctx, adoption, "a001", "chunk-one"), await item(ctx, adoption, "a002", "chunk-two"), await item(ctx, adoption, "a003", "place-one"), await item(ctx, adoption, "a004", "place-two")]
      const chunks = await Promise.all([upload(ctx, adoption, [first!], "dev_owner2"), upload(ctx, adoption, [second!], "dev_owner2")])
      expect(chunks.map(c => c.accepted)).toEqual([["a001"], ["a002"]])
      for (let i = 3; i < ADOPTION_LIMITS.maxMachines; i++) ctx.sql.exec("INSERT INTO adoption_machines(adoption,device,name) VALUES (?,?,?)", adoption, `dev_other${i}`, `other-${i}`)
      // Two machines racing for the last place.
      const last = await Promise.allSettled([upload(ctx, adoption, [third!], "dev_owner3"), upload(ctx, adoption, [fourth!], "dev_owner4")])
      expect(last.filter(r => r.status === "fulfilled")).toHaveLength(1)
      expect(last.flatMap(r => r.status === "rejected" ? [(r.reason as VaultError).toJSON()] : [])).toEqual([{ error: "conflict", message: `This batch already has ${ADOPTION_LIMITS.maxMachines} machines.` }])
      expect(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM adoption_machines WHERE adoption=?", adoption).toArray()[0]!.count).toBe(ADOPTION_LIMITS.maxMachines)
    })
  })

  it("--join: another machine of the same member fills the batch; another member's cannot", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) SELECT 'dev_owner2','laptop',backend,jwk,'dev_owner2',scope,created_at,owner_kind,owner_id FROM devices WHERE id='dev_owner'")
      const { adoption } = await start(ctx)
      expect((await upload(ctx, adoption, [await item(ctx, adoption, "a001", "from-office")])).accepted).toEqual(["a001"])
      expect((await upload(ctx, adoption, [await item(ctx, adoption, "a002", "from-laptop")], "dev_owner2")).accepted).toEqual(["a002"])
      expect(await refused(upload(ctx, adoption, [await item(ctx, adoption, "a003", "from-admin")], "dev_admin"))).toEqual({ error: "not_found", message: "No such adoption." })
      const v = await view(ctx, adoption)
      expect(v.machines).toEqual([{ device: "dev_owner", name: "office", items: 1 }, { device: "dev_owner2", name: "laptop", items: 1 }])
      expect(v.items[1]!.sources[0]!.machine).toBe("laptop")
    })
  })

  it("status of an open batch names its staged rows, only to the member's machines, and carries nothing from a value", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) SELECT 'dev_owner2','laptop',backend,jwk,'dev_owner2',scope,created_at,owner_kind,owner_id FROM devices WHERE id='dev_owner'")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "from-office"), await item(ctx, adoption, "a002", "from-office")])
      const status = await call<AdoptionStatus>(ctx, "adoption.status", { adoption }, await deviceInvocation(ctx, "dev_owner2"))
      expect(status.staged).toEqual([{ ref: "a001", slug: "from-office", machine: "office" }])
      expect(status.refused?.map(r => r.ref)).toEqual(["a002"])
      expect(JSON.stringify(status)).not.toContain(SENTINEL)
      for (const staged of status.staged ?? []) expect(Object.keys(staged).sort()).toEqual(["machine", "ref", "slug"])
      expect(await refused(call(ctx, "adoption.status", { adoption }, await deviceInvocation(ctx, "dev_admin")))).toEqual({ error: "not_found", message: "No such adoption." })
      const invocation = await deviceInvocation(ctx, "dev_owner2")
      expect(await refused(call(ctx, "adoption.status", { adoption }, invocation, { kind: "device", deviceId: "dev_owner2", workload: "wkl_task" }))).toMatchObject({ error: "forbidden" })
      await call(ctx, "adoption.cancel", { adoption }, await deviceInvocation(ctx, "dev_owner"))
      expect((await call<AdoptionStatus>(ctx, "adoption.status", { adoption }, await deviceInvocation(ctx, "dev_owner"))).staged).toBeUndefined()
    })
  })
})
