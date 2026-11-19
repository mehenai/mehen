// Fill (packages/protocol/src/fill.ts): the vault seals one field of a
// credential to the asking machine, which types it into one web page.

import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { describe, expect, it } from "vitest"
import { RULE_DEFAULT_DURATION } from "@mehen/protocol/policy-mode"
import { type ApprovalSubject, type FillResponse, KINDS, type WorkspacePendingAsk, type WorkspaceStepUpAction, createProof, fillSealContext, generateSealKeyPair, open, parseProof, parseTotp, totpCode } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { FILL_GRANTS, browserArea, fillCard, fillWorkspaceItem } from "../src/vault/areas/browser-workspace.ts"
import { workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { backupsArea } from "../src/vault/areas/backups.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { workspacePendingOps } from "../src/vault/areas/pending-workspace.ts"
import { prepareCredential, storeCredential, visibleCredential } from "../src/vault/areas/items-workspace.ts"
import { items } from "../src/vault/areas/items.ts"
import { prepareApprovedUse } from "../src/vault/areas/projects-workspace.ts"
import { accessState, setSetting, type WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { AREAS } from "../src/vault/registry.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import { credentialInput, credentialsFixture, inAccess, memberInvocation, memberPrincipal } from "./credentials-test-support.ts"
import { freshTenant } from "./helpers.ts"

const withVault = (fn: (ctx: VaultContext) => Promise<void>) => runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), (instance) => fn(instance.context))
const tables = (ctx: VaultContext) => ctx.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'fill_%' ORDER BY name").toArray().map((row) => row.name)

describe("fill's storage", () => {
  it("adds the rate-limit and one-time code tables to a tenant on the previous schema, after every area before it", async () => {
    // Appended after backups, as the registry says; areas after it are later.
    expect(AREAS.indexOf(browserArea)).toBe(AREAS.indexOf(backupsArea) + 1)
    await withVault(async (ctx) => {
      await items.putItem(ctx, { slug: "kept", kind: "api-key", provider: null, account: null, accountVerified: false, tags: [], ceiling: "placeholder", binding: { hosts: ["api.example.com"] }, policy: { default: "allow", rules: [] }, injection: null, publicFields: {}, secretFields: { key: "synthetic-kept-secret" }, description: null }, { kind: "system", reason: "test" })
      expect(tables(ctx)).toEqual(["fill_buckets", "fill_codes"])
      ctx.sql.exec("DROP TABLE fill_buckets")
      ctx.sql.exec("DROP TABLE fill_codes")
      ctx.sql.exec("DELETE FROM _migrations WHERE area = 'browser'")
      applyMigrations(ctx.sql, ctx.storage, AREAS)
      expect(tables(ctx)).toEqual(["fill_buckets", "fill_codes"])
      expect(items.getItem(ctx, "kept")).toMatchObject({ slug: "kept", browser: null })
      ctx.sql.exec("INSERT INTO fill_buckets (device, item, kind, window_start, count) VALUES ('dev_a', 'itm_a', 'secret', 0, 1)")
      expect(() => ctx.sql.exec("INSERT INTO fill_buckets (device, item, kind, window_start, count) VALUES ('dev_a', 'itm_a', 'secret', 0, 1)")).toThrow()
      ctx.sql.exec("INSERT INTO fill_codes (item, step, origin, device, count) VALUES ('itm_a', 1, 'https://github.com', 'dev_a', 1)")
      expect(() => ctx.sql.exec("INSERT INTO fill_codes (item, step, origin, device, count) VALUES ('itm_a', 1, 'https://github.com', 'dev_a', 1)")).toThrow()
      applyMigrations(ctx.sql, ctx.storage, AREAS)
      expect(ctx.sql.exec("SELECT count(*) AS n FROM fill_buckets").toArray()).toEqual([{ n: 1 }])
    })
  })
})

// Synthetic values only. The sentinels are searched for in the audit.
const PASSWORD = "synthetic-fill-password-sentinel"
const SEED = "JBSWY3DPEHPK3PXPJBSWY3DP"
const KEY = "synthetic-fill-key-sentinel"
const LOGIN = "github-login"
const DASHBOARD = "https://dashboard.example.net"

type Asker = { device: string; workload?: string }
const asker = (ctx: VaultContext, who: Asker = { device: "dev_member" }) => ({ ctx, who })

// The machine's own throwaway key pair, as the CLI makes one per fill.
async function recipient(): Promise<{ jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }; key: CryptoKey }> {
  const pair = await generateSealKeyPair()
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey) as JsonWebKey
  return { jwk: { kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y) }, key: pair.privateKey }
}
async function invocationOf(ctx: VaultContext, who: Asker): Promise<WorkspaceInvocationContext> {
  const proof = await createProof({ deviceId: who.device, ...(who.workload ? { workloadId: who.workload } : {}), sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/fill" }, { tenant: ctx.tenant })
  return { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "device", proof, method: "POST", url: "https://vault.test/v1/fill", bodyHash: "" } }
}
type Asked = { item?: string; field: string; origin?: string; page?: string; approval?: string }
type Filled = { answer: FillResponse; value: string; jti: string; key: CryptoKey; workspace: string }
// The vault's answer, opened as the machine would; or the refusal.
async function fill(ctx: VaultContext, asked: Asked, who: Asker = { device: "dev_member" }): Promise<Filled | VaultError> {
  const mine = await recipient()
  const invocation = await invocationOf(ctx, who)
  const input = { item: asked.item ?? LOGIN, field: asked.field, origin: asked.origin ?? "https://github.com", page: asked.page ?? "/login", recipient: mine.jwk, ...(asked.approval ? { approval: asked.approval } : {}) }
  try {
    const answer = await fillWorkspaceItem(ctx, { kind: "device", deviceId: who.device, ...(who.workload ? { workload: who.workload } : {}) }, input, invocation) as FillResponse
    const jti = parseProof(invocation.auth.kind === "device" ? invocation.auth.proof : "").claims.jti
    const context = fillSealContext({ workspace: ctx.tenant, item: answer.item, field: answer.field, origin: answer.origin, jti })
    return { answer, value: new TextDecoder().decode(await open(mine.key, answer.box, context)), jti, key: mine.key, workspace: ctx.tenant }
  } catch (error) {
    if (error instanceof VaultError) return error
    throw error
  }
}
const itemId = (ctx: VaultContext, slug: string) => ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug=?", slug).toArray()[0]!.id
function filled(result: Filled | VaultError): Filled {
  if (result instanceof VaultError) throw new Error(`Expected a fill, got ${result.code}: ${result.message}`)
  return result
}
function refused(result: Filled | VaultError): VaultError {
  if (!(result instanceof VaultError)) throw new Error("Expected a refusal")
  return result
}

// A device that may fill; a password login with a code, and a key the
// owner allowed to be typed into one other service's page.
function canFill(ctx: VaultContext, device = "dev_member", fillMode = true): void {
  const scope = JSON.parse(ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id=?", device).toArray()[0]!.scope) as { modes: string[] }
  ctx.sql.exec("UPDATE devices SET scope=? WHERE id=?", JSON.stringify({ ...scope, modes: fillMode ? [...scope.modes, "fill"] : scope.modes.filter((m) => m !== "fill") }), device)
}
async function seed(ctx: VaultContext, input: Parameters<typeof prepareCredential>[1]): Promise<void> {
  const prepared = await prepareCredential(ctx, input, null)
  ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
}
async function seedLogin(ctx: VaultContext, overrides: Partial<Parameters<typeof prepareCredential>[1]> = {}): Promise<void> {
  await seed(ctx, { ...credentialInput(LOGIN), kind: "password-login", ceiling: "fill", binding: { hosts: ["github.com", "*.github.com"] }, injection: null, publicFields: { url: "https://github.com/login", username: "alex@example.com" }, secretFields: { password: PASSWORD, totp_seed: SEED }, ...overrides })
}
async function seedKey(ctx: VaultContext): Promise<void> {
  await seed(ctx, { ...credentialInput("deploy-key"), ceiling: "fill", secretFields: { key: KEY } })
  ctx.sql.exec("UPDATE items SET browser=? WHERE slug='deploy-key'", JSON.stringify({ signinOrigins: [], typeInto: [DASHBOARD] }))
}
async function fixture(): Promise<string> {
  const f = await credentialsFixture()
  await inAccess(f.tenant, async (ctx) => {
    canFill(ctx)
    await seedLogin(ctx)
    await seedKey(ctx)
  })
  return f.tenant
}

async function approve(ctx: VaultContext, id: string): Promise<void> {
  const row = workspaceApproval(ctx, id)
  if (!row) throw new Error("No such approval")
  const subject = JSON.parse(row.subject) as ApprovalSubject
  const action: WorkspaceStepUpAction = { type: "approval.decide", approval: id, digest: row.digest, decision: "approve", constraints: subject.constraints }
  await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "member"), { id, decision: "approve" }, memberInvocation(ctx, "member", action))
}
const usesLeft = (ctx: VaultContext, id: string) => ctx.sql.exec<{ uses_left: number | null }>("SELECT uses_left FROM protected_use_grants WHERE approval=?", id).toArray()[0]?.uses_left
async function approved(ctx: VaultContext, asked: Asked, who?: Asker): Promise<string> {
  const ask = refused(await fill(ctx, asked, who))
  expect(ask.code).toBe("approval_required")
  const id = ask.extra.approval as string
  await approve(ctx, id)
  return id
}
const fillAudit = (ctx: VaultContext) => ctx.sql.exec<{ action: string; actor: string; target: string | null; detail: string }>("SELECT action,actor,target,detail FROM audit WHERE action='item.fill' ORDER BY seq").toArray()
const allAudit = (ctx: VaultContext) => ctx.sql.exec<{ detail: string; target: string | null }>("SELECT target,detail FROM audit").toArray().map((row) => `${row.target ?? ""} ${row.detail}`).join("\n")
// The ctx a whole test runs on, its clock fixed so codes stay in one step.
const at = (ctx: VaultContext, now: number): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { now: () => now })
const switchedOff = (ctx: VaultContext): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, BROWSER_FILL: "off" } })
// What `mehen wait` and GET /v1/pending show the asker.
const principalOf = (who: Asker) => ({ kind: "device" as const, deviceId: who.device, ...(who.workload ? { workload: who.workload } : {}) })
async function askStatus(ctx: VaultContext, who: Asker, id: string): Promise<unknown> {
  try { return await workspaceApprovalOps["approvals.status"]!.handler(ctx, principalOf(who), { id }, await invocationOf(ctx, who)) } catch (error) { if (error instanceof VaultError) return error; throw error }
}
async function pendingIds(ctx: VaultContext, who: Asker): Promise<string[]> {
  const listed = await workspacePendingOps["pending.list"]!.handler(ctx, principalOf(who), {}, await invocationOf(ctx, who)) as { pending: WorkspacePendingAsk[] }
  return listed.pending.flatMap((ask) => ask.view === "detail" ? [ask.detail.id] : [])
}

describe("POST /v1/fill's checks, in the design's order", () => {
  it("refuses with the switch off, then in a managed workspace, before reading the credential", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      expect(refused(await fill(switchedOff(ctx), { item: "no-such-item", field: "password" }))).toMatchObject({ code: "forbidden", message: "Typing into web pages is not available in this workspace." })
      setSetting(ctx, "managed", { platform: "plt_fixture", subject: "sub_fixture", member: "mem_owner", createdAt: ctx.now() })
      expect(refused(await fill(ctx, { item: "no-such-item", field: "password" }))).toMatchObject({ code: "forbidden", message: "A managed workspace's platform cannot decide fills yet, so typing into web pages is not available here." })
    })
  })

  it("refuses an unseen credential, a field its kind cannot type, a ceiling below fill, a machine without fill and an origin off the item's list", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      expect(refused(await fill(ctx, { item: "no-such-item", field: "password" })).code).toBe("not_found")
      expect(refused(await fill(ctx, { field: "key" }))).toMatchObject({ code: "bad_request", message: `"${LOGIN}" has no field "key" that can be typed into a web page.` })
      await seed(ctx, { ...credentialInput("relay-login"), kind: "password-login", ceiling: "relay", binding: { hosts: ["github.com"] }, injection: null, publicFields: { url: "https://github.com/login", username: "alex@example.com" }, secretFields: { password: PASSWORD } })
      expect(refused(await fill(ctx, { item: "relay-login", field: "username" }))).toMatchObject({ code: "mode_refused", message: `"relay-login" may not be typed into web pages: its exposure ceiling is relay.` })
      canFill(ctx, "dev_member", false)
      expect(refused(await fill(ctx, { field: "username" })).code).toBe("not_found")
      canFill(ctx)
      // A sign-in field goes only to a sign-in page, the other kind only to a listed page of another service.
      expect(refused(await fill(ctx, { field: "password", origin: "https://github.com.example.net" }))).toMatchObject({ code: "origin_mismatch", message: `https://github.com.example.net is not one of the sign-in pages for "${LOGIN}".` })
      expect(refused(await fill(ctx, { field: "password", origin: "https://gist.github.com" })).code).toBe("origin_mismatch")
      expect(refused(await fill(ctx, { item: "deploy-key", field: "key", origin: "https://api.example.com" }))).toMatchObject({ code: "origin_mismatch", message: `https://api.example.com is not a page "deploy-key" may be typed into.` })
      expect(fillAudit(ctx).map((row) => JSON.parse(row.detail).outcome)).toEqual(["refused:origin_mismatch", "refused:origin_mismatch", "refused:origin_mismatch"])
    })
  })

  it("adds the origins a human listed to the sign-in pages", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      ctx.sql.exec("UPDATE items SET browser=? WHERE slug=?", JSON.stringify({ signinOrigins: ["https://github.example.com"], typeInto: [] }), LOGIN)
      expect(filled(await fill(ctx, { field: "username", origin: "https://github.example.com" })).value).toBe("alex@example.com")
    })
  })
})

describe("what a fill needs", () => {
  it("types a username with no approval, checked, audited and rate limited, and records no exposure", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      const result = filled(await fill(ctx, { field: "username" }))
      expect(result.value).toBe("alex@example.com")
      expect(result.answer).toMatchObject({ field: "username", input: "username", label: "the username for alex@example.com", origin: "https://github.com", by: { free: true } })
      expect(ctx.sql.exec("SELECT count(*) AS n FROM approvals").toArray()).toEqual([{ n: 0 }])
      expect(fillAudit(ctx).map((row) => JSON.parse(row.detail))).toEqual([expect.objectContaining({ origin: "https://github.com", field: "username", page: "/login", outcome: "typed", approval: null })])
      expect(ctx.sql.exec("SELECT kind,count FROM fill_buckets ORDER BY kind").toArray()).toEqual([{ kind: "any", count: 1 }])
      expect(ctx.sql.exec("SELECT count(*) AS n FROM exposures WHERE source='filled'").toArray()).toEqual([{ n: 0 }])
    })
  })

  // The approval dial's Let it work (areas/approval-dial-workspace.ts)
  // covers only the relay: typing a secret into a page is still asked.
  it("still asks a person for a sign-in when the workspace is set to Let it work", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      setSetting(ctx, "approval_dial", "work")
      const ask = refused(await fill(ctx, { field: "password" }))
      expect(ask.code).toBe("approval_required")
      expect(workspaceApproval(ctx, ask.extra.approval as string)).toMatchObject({ status: "pending" })
    })
  })

  it("asks once for a sign-in, with six uses for ten minutes, and spends one use per field typed", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (rawCtx) => {
      const ctx = at(rawCtx, rawCtx.now())
      const ask = refused(await fill(ctx, { field: "password" }))
      expect(ask).toMatchObject({ code: "approval_required", extra: { approval: expect.stringMatching(/^apr_/), bindingCode: expect.any(String), next: { command: `mehen wait ${ask.extra.approval}` } } })
      const row = workspaceApproval(ctx, ask.extra.approval as string)!
      const subject = JSON.parse(row.subject) as ApprovalSubject
      expect(subject).toMatchObject({ item: LOGIN, method: "FILL", url: "https://github.com/", contentType: null, contentEncoding: null, constraints: { uses: 6, ttlSeconds: 600 } })
      expect(row.floor).toBe("[]")
      expect(row.shape).toBe(digestOf({ fill: "https://github.com", purpose: "signin" }))
      // The same ask again, from another page of the same sign-in, is the pending one.
      expect(refused(await fill(ctx, { field: "totp", page: "/sessions/two-factor" })).extra.approval).toBe(ask.extra.approval)
      await approve(ctx, ask.extra.approval as string)
      const password = filled(await fill(ctx, { field: "password", approval: ask.extra.approval as string }))
      expect(password.value).toBe(PASSWORD)
      expect(password.answer).toMatchObject({ input: "password", label: "the password for alex@example.com", by: { approval: ask.extra.approval } })
      const code = filled(await fill(ctx, { field: "totp", page: "/sessions/two-factor" }))
      const parsed = parseTotp(SEED)
      if (!parsed.ok) throw new Error(parsed.reason)
      const expected = await totpCode(parsed.totp, ctx.now())
      expect(code.value).toBe(expected.code)
      expect(code.answer).toMatchObject({ input: "one-time-code", validUntil: new Date(expected.validUntilMs).toISOString(), by: { approval: ask.extra.approval } })
      expect(filled(await fill(ctx, { field: "username" })).answer.by).toEqual({ free: true })
      expect(usesLeft(ctx, ask.extra.approval as string)).toBe(4)
      expect(ctx.sql.exec("SELECT source,device FROM exposures WHERE device IS NOT NULL ORDER BY at").toArray()).toEqual([{ source: "filled", device: "dev_member" }, { source: "filled", device: "dev_member" }])
    })
  })

  it("always asks to type into another service's page, one use at a time, and never lets a rule be remembered from it", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      const asked = { item: "deploy-key", field: "key", origin: DASHBOARD, page: "/settings/keys" }
      const first = await approved(ctx, asked)
      const row = workspaceApproval(ctx, first)!
      expect(JSON.parse(row.subject)).toMatchObject({ method: "FILL", url: `${DASHBOARD}/`, constraints: { uses: 1, ttlSeconds: 600 } })
      expect(row.floor).toBe(JSON.stringify(["sharing"]))
      expect(row.shape).toBe(digestOf({ fill: DASHBOARD, purpose: "type_into" }))
      const result = filled(await fill(ctx, asked))
      expect(result.value).toBe(KEY)
      expect(result.answer).toMatchObject({ input: "secret", by: { approval: first } })
      const again = refused(await fill(ctx, asked))
      expect(again.code).toBe("approval_required")
      expect(again.extra.approval).not.toBe(first)
      const pending = workspaceApproval(ctx, again.extra.approval as string)!
      const subject = JSON.parse(pending.subject) as ApprovalSubject
      // Even with standing rules on, no rule is ever made from a fill.
      const rulesOn = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, POLICY_RULES: "on" } })
      const remember = { kind: "rule" as const, path: "/", ttlSeconds: RULE_DEFAULT_DURATION, termsDigest: "x".repeat(43) }
      const action: WorkspaceStepUpAction = { type: "approval.decide", approval: pending.id, digest: pending.digest, decision: "approve", constraints: subject.constraints, remember }
      await expect(Promise.resolve().then(() => workspaceApprovalOps["approvals.decide"]!.handler(rulesOn, memberPrincipal(ctx, "member"), { id: pending.id, decision: "approve", remember }, memberInvocation(ctx, "member", action)))).rejects.toBeInstanceOf(VaultError)
      expect(workspaceApproval(ctx, pending.id)!.status).toBe("pending")
    })
  })

  it("lets a workload fill only in modes its device has, and its ask is its own", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      const now = ctx.now()
      ctx.sql.exec("INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES ('wl_browser','dev_member','browser-task','{}','thumb-browser',?,?,?,?)", JSON.stringify({ modes: ["fill"] }), now, now + 3_600_000, now + 3_600_000)
      ctx.sql.exec("INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES ('wl_relay','dev_member','relay-task','{}','thumb-relay',?,?,?,?)", JSON.stringify({ modes: ["relay"] }), now, now + 3_600_000, now + 3_600_000)
      expect(filled(await fill(ctx, { field: "username" }, { device: "dev_member", workload: "wl_browser" })).value).toBe("alex@example.com")
      expect(JSON.parse(fillAudit(ctx).at(-1)!.detail)).toMatchObject({ workload: "wl_browser", outcome: "typed" })
      expect(refused(await fill(ctx, { field: "username" }, { device: "dev_member", workload: "wl_relay" })).code).toBe("not_found")
      const ask = refused(await fill(ctx, { field: "password" }, { device: "dev_member", workload: "wl_browser" }))
      const id = ask.extra.approval as string
      expect(workspaceApproval(ctx, id)!.workload).toBe("wl_browser")
      // A fill-only workload waits on its own sign-in ask and lists it; the machine's other workload sees neither.
      const browser = { device: "dev_member", workload: "wl_browser" }, relay = { device: "dev_member", workload: "wl_relay" }
      expect(await askStatus(ctx, browser, id)).toMatchObject({ approval: id, status: "pending", summary: "Type the password for alex@example.com into github.com" })
      expect(await pendingIds(ctx, browser)).toEqual([id])
      expect(await askStatus(ctx, relay, id)).toMatchObject({ code: "not_found" })
      expect(await pendingIds(ctx, relay)).toEqual([])
      ctx.sql.exec("UPDATE workloads SET revoked_at=? WHERE id='wl_browser'", now)
      expect(refused(await fill(ctx, { field: "username" }, { device: "dev_member", workload: "wl_browser" })).code).toBe("workload_ended")
    })
  })
})

describe("the card a human approves", () => {
  const SIGN_IN_CARD = {
    title: "Type the password for alex@example.com into github.com",
    details: [{ label: "Page", value: "https://github.com" }, { label: "Allows", value: "This also lets it type the one-time code on https://github.com, up to 6 fields in all, for the next 10 minutes. The username needs no approval." }],
    body: null,
    warnings: [],
  }

  it("names the field, whose it is and the page, and says what the approval allows in the grant's own numbers", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      const signIn = workspaceApproval(ctx, refused(await fill(ctx, { field: "password" })).extra.approval as string)!
      expect(JSON.parse(signIn.subject).constraints).toEqual(FILL_GRANTS.signIn)
      expect(JSON.parse(signIn.presentation)).toEqual(SIGN_IN_CARD)
      // One card for every field of a sign-in, so the code joins the password's ask.
      expect(refused(await fill(ctx, { field: "totp" })).extra.approval).toBe(signIn.id)
      const other = workspaceApproval(ctx, refused(await fill(ctx, { item: "deploy-key", field: "key", origin: DASHBOARD, page: "/settings/keys" })).extra.approval as string)!
      expect(JSON.parse(other.subject).constraints).toEqual(FILL_GRANTS.typeInto)
      expect(JSON.parse(other.presentation)).toEqual({
        title: "Type the key of deploy-key into dashboard.example.net",
        details: [{ label: "Page", value: DASHBOARD }, { label: "Allows", value: "Typed once, within the next 10 minutes." }],
        body: null,
        warnings: ["This puts the credential into another service. Every time asks you first."],
      })
    })
  })

  it("takes its numbers from the grant it describes, so its words change with the grant", () => {
    const field = (kind: "password-login" | "totp" | "api-key", name: string) => KINDS[kind].fill.find((f) => f.name === name)!
    const login = { slug: LOGIN, kind: "password-login" as const, publicFields: { username: "alex@example.com" } }
    expect(fillCard(login, field("password-login", "totp"), "https://github.com", { uses: 4, ttlSeconds: 300 }).details).toEqual([{ label: "Page", value: "https://github.com" }, { label: "Allows", value: "This also lets it type the one-time code on https://github.com, up to 4 fields in all, for the next 5 minutes. The username needs no approval." }])
    expect(fillCard({ ...login, publicFields: {} }, field("password-login", "password"), "https://github.com:8443", FILL_GRANTS.signIn).title).toBe(`Type the password for ${LOGIN} into github.com:8443`)
    expect(fillCard({ slug: "github-code", kind: "totp", publicFields: {} }, field("totp", "code"), "https://github.com", { uses: 3, ttlSeconds: 120 })).toEqual({ title: "Type the one-time code for github-code into github.com", details: [{ label: "Page", value: "https://github.com" }, { label: "Allows", value: "This lets it type it on https://github.com up to 3 times, for the next 2 minutes." }], body: null, warnings: [] })
    expect(fillCard({ slug: "deploy-key", kind: "api-key", publicFields: {} }, field("api-key", "key"), DASHBOARD, { uses: 2, ttlSeconds: 60 }).details[1]).toEqual({ label: "Allows", value: "Typed up to 2 times, within the next 1 minute." })
  })

  it("spells hidden characters in whose it is, and says so in red, as a relay card does", () => {
    const card = fillCard({ slug: LOGIN, kind: "password-login", publicFields: { username: "alex\u202E@example.com" } }, KINDS["password-login"].fill.find((f) => f.name === "password")!, "https://github.com", FILL_GRANTS.signIn)
    expect(card.title).not.toContain("\u202E")
    expect(card.title).toContain("U+202E")
    expect(card.warnings).not.toEqual([])
  })

  it("keeps an ask made with earlier words: it shows and is decided with them, and a use after the change asks again and types nothing", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      // The ask exactly as the vault made it before these words (#209's card).
      const principal = { kind: "device" as const, deviceId: "dev_member" }
      const item = visibleCredential(ctx, principal, LOGIN, { context: null, mode: "fill" })
      const subject: ApprovalSubject = { item: LOGIN, method: "FILL", url: "https://github.com/", contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf({ purpose: "signin", fields: ["username", "password", "totp"] }), constraints: { uses: 6, ttlSeconds: 600 } }
      const earlier = { title: `Sign in to https://github.com with "${LOGIN}"`, details: [{ label: "Page", value: "https://github.com" }, { label: "Fields", value: "username, password, totp" }, { label: "Allows", value: "Up to 6 fields typed within 10 minutes" }], body: null, warnings: [] }
      const batch = { floor: [], shape: digestOf({ fill: "https://github.com", purpose: "signin" }), replaces: null }
      const asked = prepareApprovedUse(ctx, accessState(ctx), { principal, workspace: { id: ctx.tenant, slug: "work", name: "Work" }, presentation: earlier, mode: "fill", batch }, { id: item.id, slug: item.slug, home: item.home, configRevision: item.configRev }, null, subject, null, ctx.now())
      expect(asked.kind).toBe("required")
      const view = await workspaceApprovalOps["approvals.view"]!.handler(ctx, memberPrincipal(ctx, "member"), { id: asked.approvalId }, memberInvocation(ctx, "member")) as { view: string; approval: { title: string; details: unknown } }
      expect(view.approval).toMatchObject({ title: earlier.title, details: earlier.details })
      await approve(ctx, asked.approvalId)
      expect(workspaceApproval(ctx, asked.approvalId)!.status).toBe("approved")
      // The card is part of what the approval is bound to: a use under today's words is a new ask.
      const again = refused(await fill(ctx, { field: "password", approval: asked.approvalId }))
      expect(again.code).toBe("approval_required")
      expect(again.extra.approval).not.toBe(asked.approvalId)
      expect(JSON.parse(workspaceApproval(ctx, again.extra.approval as string)!.presentation)).toEqual(SIGN_IN_CARD)
      expect(fillAudit(ctx)).toEqual([])
      expect(usesLeft(ctx, asked.approvalId)).toBe(6)
    })
  })
})

describe("what a fill delivers", () => {
  it("seals each box to its own workspace, item, field, origin and proof, so one fill's box does not open as another", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      ctx.sql.exec("UPDATE items SET browser=? WHERE slug=?", JSON.stringify({ signinOrigins: ["https://github.example.com"], typeInto: [] }), LOGIN)
      const result = filled(await fill(ctx, { field: "username" }))
      const item = itemId(ctx, LOGIN)
      expect(result.answer.item).toBe(item)
      const right = { workspace: result.workspace, item, field: "username", origin: "https://github.com", jti: result.jti }
      expect(new TextDecoder().decode(await open(result.key, result.answer.box, fillSealContext(right)))).toBe("alex@example.com")
      for (const wrong of [{ jti: "jti_another" }, { field: "password" }, { origin: "https://github.example.com" }, { item: "itm_another" }, { workspace: "tn_Another12345" }])
        await expect(open(result.key, result.answer.box, fillSealContext({ ...right, ...wrong }))).rejects.toThrow()
    })
  })

  it("audits every fill with its origin, field and page and never a value, a private one as the owner's event", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      const id = await approved(ctx, { field: "password" })
      filled(await fill(ctx, { field: "password", approval: id }))
      const rows = fillAudit(ctx)
      expect(rows.map((row) => ({ actor: row.actor, target: row.target, detail: JSON.parse(row.detail) }))).toEqual([{ actor: "device:dev_member", target: LOGIN, detail: { item: itemId(ctx, LOGIN), origin: "https://github.com", field: "password", page: "/login", outcome: "typed", approval: id } }])
      expect(allAudit(ctx)).not.toContain(PASSWORD)
      expect(allAudit(ctx)).not.toContain(SEED)
      // A private credential's fill is its owner's event: the origin and the field, never the page or a value.
      const scope = JSON.parse(ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id='dev_member'").toArray()[0]!.scope) as Record<string, unknown>
      ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_member'", JSON.stringify({ ...scope, privateCredentials: true }))
      await seed(ctx, { ...credentialInput("own-login", { kind: "member", member: "mem_member" }), kind: "password-login", ceiling: "fill", binding: { hosts: ["github.com"] }, injection: null, publicFields: { url: "https://github.com/login", username: "kim@example.com" }, secretFields: { password: PASSWORD } })
      filled(await fill(ctx, { item: "own-login", field: "username" }))
      const own = fillAudit(ctx).at(-1)!
      expect(own.target).toBe(itemId(ctx, "own-login"))
      expect(JSON.parse(own.detail)).toMatchObject({ slug: "own-login", outcome: "typed", browser: { origin: "https://github.com", field: "username" } })
      expect(own.detail).not.toContain("/login")
    })
  })

  it("audits a one-time code secret the vault cannot read as an outcome, never the secret", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (ctx) => {
      // A seed stored before seeds were read on the way in.
      const UNREADABLE = "synthetic-unreadable-seed-sentinel"
      const opened = ctx.openField.bind(ctx)
      const unreadable = Object.assign(Object.create(ctx) as VaultContext, { openField: async (...args: Parameters<VaultContext["openField"]>) => {
        const value = await opened(...args)
        return new TextDecoder().decode(value) === SEED ? new TextEncoder().encode(UNREADABLE) : value
      } })
      const id = await approved(ctx, { field: "totp" })
      expect(refused(await fill(unreadable, { field: "totp", approval: id })).code).toBe("totp_unreadable")
      expect(fillAudit(ctx).map((row) => JSON.parse(row.detail))).toEqual([{ item: itemId(ctx, LOGIN), origin: "https://github.com", field: "totp", page: "/login", outcome: "refused:totp_unreadable", approval: null }])
      // A private credential's is its owner's event.
      const scope = JSON.parse(ctx.sql.exec<{ scope: string }>("SELECT scope FROM devices WHERE id='dev_member'").toArray()[0]!.scope) as Record<string, unknown>
      ctx.sql.exec("UPDATE devices SET scope=? WHERE id='dev_member'", JSON.stringify({ ...scope, privateCredentials: true }))
      await seed(ctx, { ...credentialInput("own-login", { kind: "member", member: "mem_member" }), kind: "password-login", ceiling: "fill", binding: { hosts: ["github.com"] }, injection: null, publicFields: { url: "https://github.com/login", username: "kim@example.com" }, secretFields: { password: PASSWORD, totp_seed: SEED } })
      const own = await approved(ctx, { item: "own-login", field: "totp" })
      expect(refused(await fill(unreadable, { item: "own-login", field: "totp", approval: own })).code).toBe("totp_unreadable")
      expect(JSON.parse(fillAudit(ctx).at(-1)!.detail)).toMatchObject({ slug: "own-login", outcome: "refused:totp_unreadable", browser: { origin: "https://github.com", field: "totp" } })
      expect(allAudit(ctx)).not.toContain(UNREADABLE)
      expect(allAudit(ctx)).not.toContain(SEED)
    })
  })
})

describe("fill's limits", () => {
  it("allows 20 secret fills an hour per item and machine, 20 codes, and 60 fills a machine, answering when to retry", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (rawCtx) => {
      const ctx = at(rawCtx, rawCtx.now())
      const id = await approved(ctx, { field: "password" })
      const item = itemId(ctx, LOGIN)
      ctx.sql.exec("INSERT INTO fill_buckets(device,item,kind,window_start,count) VALUES ('dev_member',?,'secret',?,20)", item, ctx.now() - 600_000)
      expect(refused(await fill(ctx, { field: "password", approval: id }))).toMatchObject({ code: "rate_limited", extra: { retryAfter: 3000 } })
      expect(usesLeft(ctx, id)).toBe(6)
      // The code bucket is its own.
      filled(await fill(ctx, { field: "totp" }))
      ctx.sql.exec("UPDATE fill_buckets SET count=20 WHERE kind='code'")
      expect(refused(await fill(ctx, { field: "totp" })).code).toBe("rate_limited")
      ctx.sql.exec("UPDATE fill_buckets SET count=60 WHERE kind='any'")
      expect(refused(await fill(ctx, { field: "username" })).code).toBe("rate_limited")
      // A new hour starts the count again.
      const later = at(rawCtx, ctx.now() + 3_600_000)
      expect(filled(await fill(later, { field: "username" })).value).toBe("alex@example.com")
      expect(fillAudit(ctx).map((row) => JSON.parse(row.detail).outcome)).toEqual(["refused:rate_limited", "typed", "refused:rate_limited", "refused:rate_limited", "typed"])
    })
  })

  it("sends at most three codes for one item, machine and step, and one step's code to one origin only", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (rawCtx) => {
      // The start of a 30 second step, so every code below is in it.
      const ctx = at(rawCtx, Math.floor(rawCtx.now() / 30_000) * 30_000 + 1_000)
      ctx.sql.exec("UPDATE items SET browser=? WHERE slug=?", JSON.stringify({ signinOrigins: ["https://github.example.com"], typeInto: [] }), LOGIN)
      const id = await approved(ctx, { field: "totp" })
      const codes = [filled(await fill(ctx, { field: "totp" })), filled(await fill(ctx, { field: "totp" })), filled(await fill(ctx, { field: "totp" }))]
      expect(new Set(codes.map((c) => c.value)).size).toBe(1)
      expect(refused(await fill(ctx, { field: "totp" }))).toMatchObject({ code: "rate_limited", extra: { retryAfter: 29 } })
      // Signing in on another listed page is its own ask; its code still waits for the next step.
      const elsewhere = await approved(ctx, { field: "totp", origin: "https://github.example.com" })
      expect(refused(await fill(ctx, { field: "totp", origin: "https://github.example.com", approval: elsewhere }))).toMatchObject({ code: "origin_mismatch", message: "This one-time code already went to https://github.com; wait for the next one." })
      expect([usesLeft(ctx, id), usesLeft(ctx, elsewhere)]).toEqual([3, 6])
      const next = at(rawCtx, ctx.now() + 30_000)
      expect(filled(await fill(next, { field: "totp", origin: "https://github.example.com" })).value).not.toBe(codes[0]!.value)
    })
  })

  it("keeps an item's one-time code rows for its current step and the one before only", async () => {
    const tenant = await fixture()
    await inAccess(tenant, async (rawCtx) => {
      const ctx = at(rawCtx, Math.floor(rawCtx.now() / 30_000) * 30_000 + 1_000)
      const step = Math.floor(ctx.now() / 30_000), item = itemId(ctx, LOGIN)
      for (const old of [step - 3, step - 2, step - 1]) ctx.sql.exec("INSERT INTO fill_codes(item,step,origin,device,count) VALUES (?,?,'https://github.com','dev_member',1)", item, old)
      ctx.sql.exec("INSERT INTO fill_codes(item,step,origin,device,count) VALUES ('itm_other',?,'https://example.com','dev_member',1)", step - 3)
      await approved(ctx, { field: "totp" })
      filled(await fill(ctx, { field: "totp" }))
      // Another item's steps may be another length, so its rows wait for its own next code.
      expect(ctx.sql.exec("SELECT item,step,count FROM fill_codes WHERE item=? ORDER BY step", item).toArray()).toEqual([{ item, step: step - 1, count: 1 }, { item, step, count: 1 }])
      expect(ctx.sql.exec("SELECT item,step FROM fill_codes WHERE item<>?", item).toArray()).toEqual([{ item: "itm_other", step: step - 3 }])
    })
  })
})
