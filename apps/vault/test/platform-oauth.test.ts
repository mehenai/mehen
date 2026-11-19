// The platform's OAuth connects (routes 16 to 19) and custom providers in a
// managed workspace, end to end in workerd: each call reaches the workspace
// as P1's routes hand it over, the subject's OAuth client goes in through a
// sealed intake, and a fake provider's token URL checks the client secret
// and the PKCE verifier. No live provider is ever called.
import { afterEach, describe, expect, it, vi } from "vitest"
import { CUSTOM_OAUTH_PROVIDER_ID, INITIAL_PLATFORM_DEFAULTS, importSealPublicKey, seal, PlatformConnectFinishedSchema, PlatformConnectStartedSchema, PlatformConnectStatusSchema, base64UrlEncode, customClientBinding, customItemPolicy, evaluatePolicy, managedItemPolicy, parseDestination, sha256, type CustomOAuthProvider, type PlatformConnectFinished, type PlatformConnectStarted } from "@mehen/protocol"
import type { ConnectStatus } from "@mehen/protocol/api"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { refreshManagedPlatform, registerManagedDirectory } from "../src/vault/managed-platform.ts"
import { checkedCredential } from "../src/vault/areas/items-workspace.ts"
import { oauthArea } from "../src/vault/areas/oauth.ts"
import { customProviderOf, workspaceAccessToken } from "../src/vault/areas/oauth-workspace.ts"
import { AREAS } from "../src/vault/registry.ts"
import { platformOAuthRoutes } from "../src/routes/platform-oauth.ts"
import { fetchWorker, freshTenant } from "./helpers.ts"
import { accessSnapshot, inAccess } from "./access-test-support.ts"
import { SUBJECT, afterDeletionBegan, invokeAs, json, managedSubject, platform, platformAuth, refused, signed, sql } from "./managed-support.ts"

const CALLBACK = "https://app.globex.ai/oauth/callback"
const GOOGLE_SECRET = "google-client-secret-never-returned"
const ACME_SECRET = "acme-client-secret-never-returned"

const acme: CustomOAuthProvider = {
  name: "Acme CRM",
  authorizeUrl: "https://auth.acme-crm.example.com/authorize",
  tokenUrl: "https://auth.acme-crm.example.com/oauth/token",
  scopes: ["contacts.read", "contacts.write"],
  pkce: "S256",
  clientAuth: "client_secret_basic",
  authorizeParams: { audience: "crm-api" },
  hosts: ["api.acme-crm.example.com"],
}

const cleanups: (() => void)[] = []
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup()
  setUpstreamFetch(null)
  vi.useRealTimers()
})

type Grant = { challenge: string | null; redirectUri: string; scope: string | null }

// One provider's token URL, and Google's userinfo for catalogue identities.
// The token URL takes a code only with the client's own secret (or, for a
// public client, none at all), the redirect URI it was issued for and, when
// the authorisation carried a challenge, the matching verifier.
class FakeProvider {
  readonly codes = new Map<string, Grant>()
  readonly tokenBodies: URLSearchParams[] = []
  readonly tokenHeaders: (string | null)[] = []
  readonly sent: string[] = []
  readonly refreshToken = "fake-refresh-1"
  accessToken = "fake-access-1"
  identity = { sub: "google-subject-1", email: "jim@example.com" }
  grantedScope: string | null = null
  constructor(readonly opts: { tokenUrl: string; clientId: string; clientSecret: string | null; clientAuth: "post" | "basic" | "none" }) {}

  // The person consents at the provider, which sends them to the platform's
  // callback with the state and a code bound to what the URL carried.
  consent(authorizeUrl: string): { state: string; code: string } {
    const url = new URL(authorizeUrl)
    const code = `code-${this.sent.length}-${this.codes.size + 1}`
    this.codes.set(code, { challenge: url.searchParams.get("code_challenge"), redirectUri: url.searchParams.get("redirect_uri") ?? "", scope: url.searchParams.get("scope") })
    return { state: url.searchParams.get("state") ?? "", code }
  }

  private clientOk(header: string | null, body: URLSearchParams): boolean {
    const { clientId, clientSecret, clientAuth } = this.opts
    if (clientAuth === "none") return body.get("client_id") === clientId && !body.has("client_secret") && header === null
    if (clientAuth === "post") return body.get("client_id") === clientId && body.get("client_secret") === clientSecret
    return header === `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret ?? "")}`)}` && !body.has("client_secret")
  }

  readonly fetch = async (request: Request): Promise<Response> => {
    this.sent.push(request.url)
    if (request.url === "https://openidconnect.googleapis.com/v1/userinfo") {
      return request.headers.get("authorization") === `Bearer ${this.accessToken}` ? Response.json(this.identity) : new Response("no", { status: 401 })
    }
    if (request.url !== this.opts.tokenUrl || request.method !== "POST") return new Response("not here", { status: 404 })
    const body = new URLSearchParams(new TextDecoder().decode(await request.arrayBuffer()))
    const header = request.headers.get("authorization")
    this.tokenBodies.push(body)
    this.tokenHeaders.push(header)
    if (!this.clientOk(header, body)) return Response.json({ error: "invalid_client" }, { status: 401 })
    if (body.get("grant_type") === "refresh_token") {
      if (body.get("refresh_token") !== this.refreshToken) return Response.json({ error: "invalid_grant" }, { status: 400 })
      this.accessToken = `${this.accessToken}-r`
      return Response.json({ access_token: this.accessToken, expires_in: 3600 })
    }
    const grant = this.codes.get(body.get("code") ?? "")
    this.codes.delete(body.get("code") ?? "")
    if (!grant || body.get("redirect_uri") !== grant.redirectUri) return Response.json({ error: "invalid_grant" }, { status: 400 })
    if (grant.challenge !== null && base64UrlEncode(await sha256(body.get("code_verifier") ?? "")) !== grant.challenge) return Response.json({ error: "invalid_grant" }, { status: 400 })
    const scope = this.grantedScope ?? grant.scope
    return Response.json({ access_token: this.accessToken, refresh_token: this.refreshToken, expires_in: 3600, ...(scope !== null ? { scope } : {}) })
  }
}

function google(): FakeProvider {
  const provider = new FakeProvider({ tokenUrl: "https://oauth2.googleapis.com/token", clientId: "jim-google-client", clientSecret: GOOGLE_SECRET, clientAuth: "post" })
  setUpstreamFetch(provider.fetch)
  return provider
}

function acmeProvider(definition: CustomOAuthProvider = acme): FakeProvider {
  const provider = new FakeProvider({ tokenUrl: definition.tokenUrl, clientId: "jim-acme-client", clientSecret: definition.clientAuth === "none" ? null : ACME_SECRET, clientAuth: definition.clientAuth === "client_secret_post" ? "post" : definition.clientAuth === "client_secret_basic" ? "basic" : "none" })
  setUpstreamFetch(provider.fetch)
  return provider
}

async function subject(limits: Parameters<typeof managedSubject>[0] = {}) {
  const f = await managedSubject(limits)
  cleanups.push(f.restore)
  const call = {
    start: (body: Record<string, unknown>) => platform<PlatformConnectStarted>(f.tenant, "platform.connects.start", { body: { redirectUri: CALLBACK, ...body } }),
    finish: (body: Record<string, unknown>) => platform<PlatformConnectFinished>(f.tenant, "platform.connects.finish", { body }),
    status: (connect: string) => platform<ConnectStatus>(f.tenant, "platform.connects.get", { params: { connect } }),
    cancel: (connect: string) => platform<Record<string, never>>(f.tenant, "platform.connects.cancel", { params: { connect }, body: {} }),
    refused: (op: string, input: unknown) => refused(invokeAs(f.tenant, op, input, platformAuth())),
    // The subject's own Google app, and an app with its own provider
    // definition, each through the platform's sealed intake.
    googleClient: () => f.intake("google-oauth-client", { template: "google-oauth-client" }, { client_secret: GOOGLE_SECRET }, { client_id: "jim-google-client" }),
    customClient: (definition: CustomOAuthProvider = acme, slug = "acme-client") => f.intake(slug, { customProvider: definition }, { client_secret: ACME_SECRET }, { client_id: "jim-acme-client" }),
    // The platform's row is read at most every 30 seconds; a test that
    // changes it reads it again at once.
    reread: () => inAccess(f.tenant, async (ctx) => { await refreshManagedPlatform(ctx, true) }),
    audit: async () => JSON.stringify(await sql(f.tenant, "SELECT * FROM audit")),
    customProvider: async (slug: string) => (await sql<{ custom_provider: string | null }>(f.tenant, "SELECT custom_provider FROM items WHERE slug=?", slug))[0]?.custom_provider ?? null,
  }
  return { ...f, ...call }
}

describe("platform connect start", () => {
  it("gives the provider's URL with the subject's own client id, the platform's callback and a PKCE S256 challenge", async () => {
    const f = await subject()
    await f.googleClient()
    google()
    const started = PlatformConnectStartedSchema.parse(await f.start({ provider: "google-gmail", slug: "gmail", scopes: ["gmail.readonly"] }))
    const url = new URL(started.authorizeUrl)
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth")
    expect(url.searchParams.get("client_id")).toBe("jim-google-client")
    expect(url.searchParams.get("redirect_uri")).toBe(CALLBACK)
    expect(url.searchParams.get("response_type")).toBe("code")
    expect(url.searchParams.get("code_challenge_method")).toBe("S256")
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(url.searchParams.get("state")?.length).toBeGreaterThanOrEqual(32)
    expect(url.searchParams.get("scope")).toBe("openid email https://www.googleapis.com/auth/gmail.readonly")
    expect(url.searchParams.get("access_type")).toBe("offline")
    // Only the state's hash is kept, never the state or the verifier in the clear.
    const state = url.searchParams.get("state") ?? ""
    expect(JSON.stringify(await sql(f.tenant, "SELECT * FROM workspace_credential_requests"))).not.toContain(state)
    expect(await sql(f.tenant, "SELECT connect FROM platform_connect_states")).toEqual([{ connect: started.connect }])
  })

  it("applies the platform's defaults: its providers, its default scopes and its tags, and its limits", async () => {
    const f = await subject({ openRequestsPerSubject: 2 })
    await f.googleClient()
    f.directory.defaults = { ...INITIAL_PLATFORM_DEFAULTS, providers: ["google-gmail"], scopes: { "google-gmail": ["gmail.readonly"] }, tags: ["globex"] }
    await f.reread()
    const started = await f.start({ provider: "google-gmail", slug: "gmail", tags: ["mail"] })
    expect(new URL(started.authorizeUrl).searchParams.get("scope")).toBe("openid email https://www.googleapis.com/auth/gmail.readonly")
    const [row] = await sql<{ payload: string }>(f.tenant, "SELECT payload FROM workspace_credential_requests WHERE id=?", started.connect)
    expect((JSON.parse(row!.payload) as { tags: string[] }).tags).toEqual(["globex", "mail"])
    expect(await f.refused("platform.connects.start", { body: { provider: "google-calendar", slug: "calendar", redirectUri: CALLBACK } })).toEqual({ error: "bad_request", message: "This platform does not offer Google Calendar." })
    await f.start({ provider: "google-gmail", slug: "gmail-2" })
    expect(await f.refused("platform.connects.start", { body: { provider: "google-gmail", slug: "gmail-3", redirectUri: CALLBACK } })).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
  })

  it("counts the subject's open intakes and connects for new items with its items, so connects cannot carry it past its limit", async () => {
    const f = await subject({ itemsPerSubject: 3, openRequestsPerSubject: 10 })
    await f.googleClient()
    google()
    // One item and two open intakes for new ones: the limit is reached.
    await platform(f.tenant, "platform.intakes.create", { body: { slug: "openai-a", service: { template: "openai" } } })
    const second = await platform<{ intake: string }>(f.tenant, "platform.intakes.create", { body: { slug: "openai-b", service: { template: "openai" } } })
    expect(await f.refused("platform.connects.start", { body: { provider: "google-gmail", slug: "gmail", redirectUri: CALLBACK } })).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
    await platform(f.tenant, "platform.intakes.cancel", { params: { intake: second.intake }, body: {} })
    // A connect for a new item counts as one, against connects and intakes alike.
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    expect(await f.refused("platform.connects.start", { body: { provider: "google-gmail", slug: "gmail-2", redirectUri: CALLBACK } })).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
    expect(await f.refused("platform.intakes.create", { body: { slug: "openai-c", service: { template: "openai" } } })).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
    // Starting the same name again replaces the open connect, so it fits.
    expect((await f.start({ provider: "google-gmail", slug: "gmail" })).connect).not.toBe(started.connect)
  })

  it("never lets open intakes and connects together end past the item limit", async () => {
    const f = await subject({ itemsPerSubject: 4, openRequestsPerSubject: 10 })
    await f.googleClient()
    await f.intake("openai-a", { template: "openai" }, { key: "sk-test-not-real-0001" })
    // Two items and two open intakes: further intakes and connects are refused.
    const open = await Promise.all(["openai-b", "openai-c"].map((slug) => platform<{ intake: string; sealKey: { jwk: JsonWebKey } }>(f.tenant, "platform.intakes.create", { body: { slug, service: { template: "openai" } } })))
    const provider = google()
    for (const slug of ["gmail-1", "gmail-2"]) expect(await f.refused("platform.connects.start", { body: { provider: "google-gmail", slug, redirectUri: CALLBACK } }), slug).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
    for (const opened of open) await platform(f.tenant, "platform.intakes.submit", { params: { intake: opened.intake }, body: { sealed: { key: await seal(await importSealPublicKey(opened.sealKey.jwk), "sk-test-not-real-0002", `intake/${opened.intake}/key`) } } })
    expect(await sql(f.tenant, "SELECT count(*) AS count FROM items")).toEqual([{ count: 4 }])
    expect(provider.sent).toEqual([])
  })

  it("refuses a client that is missing, of another provider, or carries no definition when no provider is named", async () => {
    const f = await subject()
    expect(await f.refused("platform.connects.start", { body: { provider: "google-gmail", slug: "gmail", redirectUri: CALLBACK } })).toMatchObject({ error: "not_found" })
    await f.googleClient()
    expect(await f.refused("platform.connects.start", { body: { provider: "github-oauth", client: "google-oauth-client", slug: "github", redirectUri: CALLBACK } })).toEqual({ error: "not_found", message: "No usable OAuth client." })
    expect(await f.refused("platform.connects.start", { body: { client: "google-oauth-client", slug: "custom", redirectUri: CALLBACK } })).toEqual({ error: "not_found", message: "No usable OAuth client." })
    expect(await sql(f.tenant, "SELECT * FROM workspace_credential_requests WHERE kind='connect'")).toEqual([])
  })

  it("starting again for the same name replaces the open connect and its state", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const first = await f.start({ provider: "google-gmail", slug: "gmail" })
    const second = await f.start({ provider: "google-gmail", slug: "gmail" })
    expect(second.connect).not.toBe(first.connect)
    expect(PlatformConnectStatusSchema.parse(await f.status(first.connect)).status).toBe("failed")
    expect(await f.refused("platform.connects.finish", { body: provider.consent(first.authorizeUrl) })).toMatchObject({ error: "conflict" })
    expect(provider.tokenBodies).toHaveLength(0)
  })
})

describe("platform connect finish", () => {
  it("exchanges the code with the subject's client secret, the verifier and the platform's callback, and stores the connection", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail", scopes: ["gmail.modify"] })
    const finished = PlatformConnectFinishedSchema.parse(await f.finish(provider.consent(started.authorizeUrl)))
    expect(finished).toMatchObject({ connect: started.connect, status: "completed", item: { slug: "gmail", kind: "oauth-connection", provider: "google-gmail", account: "jim@example.com", accountVerified: true, hosts: ["gmail.googleapis.com"] } })
    const body = provider.tokenBodies[0]!
    expect(body.get("grant_type")).toBe("authorization_code")
    expect(body.get("client_id")).toBe("jim-google-client")
    expect(body.get("client_secret")).toBe(GOOGLE_SECRET)
    expect(body.get("redirect_uri")).toBe(CALLBACK)
    expect(body.get("code_verifier")?.length).toBeGreaterThanOrEqual(43)
    const status = PlatformConnectStatusSchema.parse(await f.status(started.connect))
    expect(status).toMatchObject({ status: "completed", account: "jim@example.com", item: { slug: "gmail" } })
    // No answer and no audit row carries a secret, the verifier or a token;
    // the rows the platform caused name it.
    const audit = await f.audit()
    const seen = JSON.stringify([started, finished, status]) + audit
    for (const secret of [GOOGLE_SECRET, body.get("code_verifier") ?? "", provider.accessToken, provider.refreshToken]) expect(seen).not.toContain(secret)
    const rows = await sql<{ actor: string; action: string }>(f.tenant, "SELECT actor,action FROM audit WHERE action IN ('oauth.connect_start','oauth.connect','oauth.connect_finish')")
    expect(rows.map((r) => r.action).sort()).toEqual(["oauth.connect", "oauth.connect_finish", "oauth.connect_start"])
    for (const row of rows) expect(row.actor).toMatch(/^platform:plt_/)
  })

  it("checks the item limit again when it stores a new connection: at the limit it fails, keeps nothing and hands the grant back", async () => {
    const f = await subject({ itemsPerSubject: 2 })
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    // An intake a workload asked for fills the last place while the person signs in.
    const task = await f.workload(await f.device())
    const asked = await json<{ intake: string }>(await signed(f.tenant, task, "/v1/intakes", { kind: "api-key", slug: "openai-main", provider: "openai", reason: "The agent needs OpenAI.", home: "workspace" }), 201)
    const sealKey = await json<{ jwk: JsonWebKey }>(await fetchWorker("/v1/seal-key"))
    await platform(f.tenant, "platform.intakes.submit", { params: { intake: asked.intake }, body: { sealed: { key: await seal(await importSealPublicKey(sealKey.jwk), "sk-test-not-real-0001", `intake/${asked.intake}/key`) } } })
    expect(await f.refused("platform.connects.finish", { body: provider.consent(started.authorizeUrl) })).toEqual({ error: "quota_exceeded", message: "That is past this platform's limit." })
    expect(provider.sent).toContain("https://oauth2.googleapis.com/revoke")
    expect(PlatformConnectStatusSchema.parse(await f.status(started.connect)).status).toBe("failed")
    expect(await sql(f.tenant, "SELECT slug FROM items ORDER BY slug")).toEqual([{ slug: "google-oauth-client" }, { slug: "openai-main" }])
    const [finish] = await sql<{ detail: string }>(f.tenant, "SELECT detail FROM audit WHERE action='oauth.connect_finish'")
    expect(JSON.parse(finish!.detail)).toMatchObject({ outcome: "failed", reason: "quota" })
    expect(await f.audit()).not.toContain(provider.accessToken)
  })

  it("uses the state once: a second finish is a conflict and reaches no provider", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    const callback = provider.consent(started.authorizeUrl)
    await f.finish(callback)
    const sends = provider.sent.length
    expect(await f.refused("platform.connects.finish", { body: callback })).toEqual({ error: "conflict", message: "This sign-in has already been used." })
    expect(await f.refused("platform.connects.finish", { body: { state: "s".repeat(43), code: "code-x" } })).toEqual({ error: "not_found", message: "No such connection." })
    expect(provider.sent).toHaveLength(sends)
  })

  it("is not_found for another subject, whose workspace never sees the state, and leaves it for its own subject", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    const callback = provider.consent(started.authorizeUrl)
    const other = "globex_subject_0002", tenant = freshTenant()
    f.directory.workspaces.set(tenant, { subject: other, status: "creating" })
    await platform(tenant, "platform.subjects.ensure", { body: {} }, platformAuth(other))
    expect(await refused(invokeAs(tenant, "platform.connects.finish", { body: callback }, platformAuth(other)))).toEqual({ error: "not_found", message: "No such connection." })
    // Naming the other subject against this workspace finds no subject at all.
    expect(await refused(invokeAs(f.tenant, "platform.connects.finish", { body: callback }, platformAuth(other)))).toMatchObject({ error: "not_found" })
    expect(provider.tokenBodies).toHaveLength(0)
    expect(await f.finish(callback)).toMatchObject({ connect: started.connect, status: "completed" })
  })

  it("fails without storing anything for a refusal, a wrong verifier, a wider grant and another account", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const denied = await f.start({ provider: "google-gmail", slug: "gmail" })
    expect(await f.finish({ state: provider.consent(denied.authorizeUrl).state, error: "access_denied" })).toEqual({ connect: denied.connect, status: "failed", reason: "denied" })
    // The code was issued for another challenge: the vault's verifier does not match it.
    const forged = await f.start({ provider: "google-gmail", slug: "gmail" })
    const forgedCallback = provider.consent(forged.authorizeUrl)
    provider.codes.set(forgedCallback.code, { ...provider.codes.get(forgedCallback.code)!, challenge: base64UrlEncode(await sha256("another verifier")) })
    expect(await f.finish(forgedCallback)).toEqual({ connect: forged.connect, status: "failed", reason: "provider" })
    const wider = await f.start({ provider: "google-gmail", slug: "gmail", scopes: ["gmail.readonly"] })
    provider.grantedScope = "openid email https://mail.google.com/"
    expect(await f.finish(provider.consent(wider.authorizeUrl))).toEqual({ connect: wider.connect, status: "failed", reason: "wider" })
    provider.grantedScope = null
    const other = await f.start({ provider: "google-gmail", slug: "gmail", expect: "someone@example.com" })
    expect(await f.finish(provider.consent(other.authorizeUrl))).toEqual({ connect: other.connect, status: "failed", reason: "mismatch" })
    expect(PlatformConnectStatusSchema.parse(await f.status(other.connect)).status).toBe("mismatch")
    expect(await sql(f.tenant, "SELECT slug FROM items WHERE slug='gmail'")).toEqual([])
  })

  it("answers upstream_failed when the provider does not answer, and the state is spent", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    const callback = provider.consent(started.authorizeUrl)
    setUpstreamFetch(async () => { throw new Error("provider unreachable") })
    expect(await f.refused("platform.connects.finish", { body: callback })).toMatchObject({ error: "upstream_failed" })
    setUpstreamFetch(provider.fetch)
    expect(await f.refused("platform.connects.finish", { body: callback })).toMatchObject({ error: "conflict" })
  })

  it("pins a reconnect to the provider account that was connected", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    await f.finish(provider.consent((await f.start({ provider: "google-gmail", slug: "gmail" })).authorizeUrl))
    const [before] = await sql<{ version: number }>(f.tenant, "SELECT version FROM items WHERE slug='gmail'")
    provider.identity = { sub: "google-subject-2", email: "jim@example.com" }
    const again = await f.start({ provider: "google-gmail", slug: "gmail" })
    expect(await f.finish(provider.consent(again.authorizeUrl))).toMatchObject({ status: "failed", reason: "mismatch" })
    expect(await sql(f.tenant, "SELECT version FROM items WHERE slug='gmail'")).toEqual([before])
  })

  it("writes nothing for a connect call admitted just before its subject's deletion began, and reaches no provider", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    const callback = provider.consent(started.authorizeUrl)
    const before = await accessSnapshot(f.tenant)
    for (const [op, input] of [["platform.connects.start", { body: { provider: "google-gmail", slug: "gmail-2", redirectUri: CALLBACK } }], ["platform.connects.finish", { body: callback }], ["platform.connects.cancel", { params: { connect: started.connect }, body: {} }]] as const) {
      expect(await afterDeletionBegan(f.tenant, op, input), op).toEqual({ error: "not_found", message: "No such subject." })
    }
    expect(await accessSnapshot(f.tenant)).toBe(before)
    expect(provider.sent).toEqual([])
  })

  // A platform connect pins its client too: once that client's secret is
  // replaced, the connect ends with the reason, and the callback finds it ended.
  it("ends an open platform connect when its client's secret is replaced, saying so", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    await inAccess(f.tenant, async (ctx) => {
      const { prepareCredential, storeCredential } = await import("../src/vault/areas/items-workspace.ts")
      const client = checkedCredential(ctx, "google-oauth-client")!
      const replaced = await prepareCredential(ctx, { ...client, secretFields: { client_secret: "google-client-secret-replaced" } }, client)
      ctx.storage.transactionSync(() => storeCredential(ctx, replaced, { kind: "system", reason: "test" } as never, "item.rotate"))
    })
    expect(await f.status(started.connect)).toMatchObject({ status: "failed", message: expect.stringContaining("ask for a new link") })
    expect(await f.refused("platform.connects.finish", { body: provider.consent(started.authorizeUrl) })).toMatchObject({ error: expect.any(String) })
    expect(provider.tokenBodies).toEqual([])
  })

  it("cancel spends the state, so a late callback is a conflict", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    const started = await f.start({ provider: "google-gmail", slug: "gmail" })
    expect(await f.cancel(started.connect)).toEqual({})
    expect(await f.refused("platform.connects.finish", { body: provider.consent(started.authorizeUrl) })).toEqual({ error: "conflict", message: "This sign-in has already been used." })
    expect(provider.tokenBodies).toHaveLength(0)
  })
})

describe("refresh", () => {
  it("refreshes a catalogue connection the platform made with the subject's client secret", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    await f.finish(provider.consent((await f.start({ provider: "google-gmail", slug: "gmail" })).authorizeUrl))
    const token = await inAccess(f.tenant, async (ctx) => {
      const item = checkedCredential(ctx, "gmail")!
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
      return workspaceAccessToken(ctx, item)
    })
    expect(token).toBe("fake-access-1-r")
    expect(provider.tokenBodies.at(-1)?.get("grant_type")).toBe("refresh_token")
    expect(provider.tokenBodies.at(-1)?.get("client_secret")).toBe(GOOGLE_SECRET)
  })

  // No device can reconnect a managed workspace's connection: its
  // description says the platform does, so mehen's hint names no command.
  it("tells a device reading the connection that the platform reconnects it", async () => {
    const f = await subject()
    await f.googleClient()
    await f.finish(google().consent((await f.start({ provider: "google-gmail", slug: "gmail" })).authorizeUrl))
    const machine = await f.device()
    const described = await json<{ connection?: Record<string, unknown> }>(await signed(f.tenant, machine, "/v1/items/gmail"))
    expect(described.connection).toMatchObject({ reconnect: "platform" })
  })

  it("waits while the platform is suspended, without calling the provider", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    await f.finish(provider.consent((await f.start({ provider: "google-gmail", slug: "gmail" })).authorizeUrl))
    const sends = provider.sent.length
    f.directory.platform.status = "suspended"
    const waited = await inAccess(f.tenant, async (ctx) => {
      await refreshManagedPlatform(ctx, true)
      const item = checkedCredential(ctx, "gmail")!
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
      await oauthArea.alarm!(ctx, `workspace-refresh:${item.id}`)
      return ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='oauth' AND key=?", `workspace-refresh:${item.id}`).toArray()[0]?.due_at ?? 0
    })
    expect(waited).toBeGreaterThan(Date.now())
    expect(provider.sent).toHaveLength(sends)
  })

  it("waits while the platform cannot be read, never judging by the row it held from before", async () => {
    const f = await subject()
    await f.googleClient()
    const provider = google()
    await f.finish(provider.consent((await f.start({ provider: "google-gmail", slug: "gmail" })).authorizeUrl))
    const sends = provider.sent.length
    // The row held is the active one, past its interval; the next read fails.
    vi.useFakeTimers({ toFake: ["Date"] })
    vi.setSystemTime(Date.now() + 31_000)
    const restore = registerManagedDirectory({ async read() { throw new Error("D1 unavailable") }, async purged() {} })
    try {
      const waited = await inAccess(f.tenant, async (ctx) => {
        const item = checkedCredential(ctx, "gmail")!
        ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
        await oauthArea.alarm!(ctx, `workspace-refresh:${item.id}`)
        return ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='oauth' AND key=?", `workspace-refresh:${item.id}`).toArray()[0]?.due_at ?? 0
      })
      expect(waited).toBeGreaterThan(Date.now())
      expect(provider.sent).toHaveLength(sends)
    } finally {
      restore()
    }
  })
})

describe("custom providers", () => {
  it("connects end to end: the definition's URLs, client_secret_basic, the verifier, its hosts and injection, and a fail-closed policy", async () => {
    const f = await subject()
    await f.customClient()
    const provider = acmeProvider()
    const started = PlatformConnectStartedSchema.parse(await f.start({ client: "acme-client", slug: "acme", scopes: ["contacts.read"] }))
    const url = new URL(started.authorizeUrl)
    expect(url.origin + url.pathname).toBe(acme.authorizeUrl)
    expect(Object.fromEntries(url.searchParams)).toMatchObject({ client_id: "jim-acme-client", redirect_uri: CALLBACK, scope: "contacts.read", audience: "crm-api", code_challenge_method: "S256" })
    const finished = await f.finish(provider.consent(started.authorizeUrl))
    expect(finished).toMatchObject({ status: "completed", item: { slug: "acme", provider: null, account: null, accountVerified: false, hosts: ["api.acme-crm.example.com"], policy: customItemPolicy(false) } })
    expect(provider.tokenBodies[0]?.has("client_secret")).toBe(false)
    expect(provider.tokenBodies[0]?.get("code_verifier")?.length).toBeGreaterThanOrEqual(43)
    const item = await inAccess(f.tenant, (ctx) => checkedCredential(ctx, "acme")!)
    expect(item.binding).toEqual({ hosts: ["api.acme-crm.example.com"] })
    expect(item.injection).toEqual({ in: "header", name: "Authorization", format: "Bearer {access_token}" })
    expect(item.policy).toEqual(customItemPolicy(false))
    // With no template, every request is held unless the platform let reads through.
    const read = parseDestination("GET", "https://api.acme-crm.example.com/contacts")
    if (!read.ok) throw new Error("destination")
    expect(evaluatePolicy(managedItemPolicy(item.provider, INITIAL_PLATFORM_DEFAULTS), read.destination).action).toBe("approve")
    expect(evaluatePolicy(managedItemPolicy(item.provider, { ...INITIAL_PLATFORM_DEFAULTS, customReads: "allow" }), read.destination).action).toBe("allow")
    // The audit names the provider's host, never a token or the secret.
    const audit = await f.audit()
    expect(audit).toContain("auth.acme-crm.example.com")
    for (const secret of [ACME_SECRET, provider.accessToken, provider.refreshToken, provider.tokenBodies[0]?.get("code_verifier") ?? ""]) expect(audit + JSON.stringify(finished)).not.toContain(secret)
  })

  it("lets a relay through the connection only to the definition's hosts, with the token injected", async () => {
    const f = await subject()
    await f.customClient()
    const provider = acmeProvider()
    await f.finish(provider.consent((await f.start({ client: "acme-client", slug: "acme" })).authorizeUrl))
    f.directory.defaults = { ...INITIAL_PLATFORM_DEFAULTS, customReads: "allow" }
    await f.reread()
    const machine = await f.device()
    const task = await f.workload(machine)
    const upstream: Request[] = []
    setUpstreamFetch(async (request) => { upstream.push(request); return Response.json({ contacts: [] }) })
    await json(await signed(f.tenant, task, "/v1/relay", { item: "acme", method: "GET", url: "https://api.acme-crm.example.com/contacts", headers: [] }))
    expect(upstream[0]?.headers.get("authorization")).toBe(`Bearer ${provider.accessToken}`)
    const elsewhere = await signed(f.tenant, task, "/v1/relay", { item: "acme", method: "GET", url: "https://api.attacker.example.com/contacts", headers: [] })
    expect(elsewhere.status).toBeGreaterThanOrEqual(400)
    expect(upstream).toHaveLength(1)
  })

  it("asks for every scope of the definition when none are named, and refuses one outside it", async () => {
    const f = await subject()
    await f.customClient({ ...acme, scopeSeparator: "," })
    acmeProvider()
    const started = await f.start({ client: "acme-client", slug: "acme" })
    expect(new URL(started.authorizeUrl).searchParams.get("scope")).toBe("contacts.read,contacts.write")
    expect(await f.refused("platform.connects.start", { body: { client: "acme-client", slug: "acme", scopes: ["admin"], redirectUri: CALLBACK } })).toEqual({ error: "bad_request", message: '"admin" is not a scope Acme CRM allows.' })
  })

  it("refreshes at the definition's token URL, with the host in the audit", async () => {
    const f = await subject()
    const post: CustomOAuthProvider = { ...acme, clientAuth: "client_secret_post" }
    await f.customClient(post)
    const provider = acmeProvider(post)
    await f.finish(provider.consent((await f.start({ client: "acme-client", slug: "acme" })).authorizeUrl))
    const token = await inAccess(f.tenant, async (ctx) => {
      const item = checkedCredential(ctx, "acme")!
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", ctx.now() - 1, item.id)
      return workspaceAccessToken(ctx, item)
    })
    expect(token).toBe("fake-access-1-r")
    const body = provider.tokenBodies.at(-1)!
    expect(body.get("grant_type")).toBe("refresh_token")
    expect(body.get("client_secret")).toBe(ACME_SECRET)
    const [attempt] = await sql<{ detail: string }>(f.tenant, "SELECT detail FROM audit WHERE action='oauth.refresh_attempt' ORDER BY seq DESC LIMIT 1")
    expect(JSON.parse(attempt!.detail)).toMatchObject({ provider: CUSTOM_OAUTH_PROVIDER_ID, host: "auth.acme-crm.example.com" })
    expect(attempt!.detail).not.toContain(provider.refreshToken)
  })

  // A custom provider's rotation is not known, so it is treated as strict:
  // a lost refresh answer keeps its marker, the stored token is used while
  // it lasts, and no second refresh goes out inside the window.
  it("keeps using a token that still works after a refresh whose answer was lost, sending no second refresh, and refuses only once it has expired", async () => {
    const f = await subject()
    await f.customClient()
    const provider = acmeProvider()
    await f.finish(provider.consent((await f.start({ client: "acme-client", slug: "acme" })).authorizeUrl))
    await inAccess(f.tenant, async (ctx) => {
      const item = checkedCredential(ctx, "acme")!
      const now = ctx.now()
      ctx.sql.exec("UPDATE workspace_oauth_connections SET expires_at=? WHERE item=?", now + 30_000, item.id)
      let sends = 0
      setUpstreamFetch(async () => { sends++; throw new Error("connection reset") })
      const at = (ms: number) => ({ ...ctx, now: () => ms })
      expect(await workspaceAccessToken(at(now), checkedCredential(ctx, "acme")!)).toBe(provider.accessToken)
      expect(await workspaceAccessToken(at(now + 1_000), checkedCredential(ctx, "acme")!)).toBe(provider.accessToken)
      expect(sends).toBe(1)
      await expect(workspaceAccessToken(at(now + 31_000), checkedCredential(ctx, "acme")!)).rejects.toMatchObject({ code: "refresh_retrying" })
      expect(sends).toBe(1)
    })
  })

  it("a public client sends no secret and always uses PKCE; one stored without PKCE is refused", async () => {
    const f = await subject()
    const publicClient: CustomOAuthProvider = { ...acme, clientAuth: "none", pkce: "S256" }
    // Route 13 does not add public clients yet, so the client is
    // stored as a confidential one and its definition made public here.
    await f.customClient(acme)
    await sql(f.tenant, "UPDATE items SET custom_provider=? WHERE slug='acme-client'", JSON.stringify(publicClient))
    const provider = acmeProvider(publicClient)
    const started = await f.start({ client: "acme-client", slug: "acme" })
    expect(await f.finish(provider.consent(started.authorizeUrl))).toMatchObject({ status: "completed" })
    expect(provider.tokenBodies[0]?.get("code_verifier")).toBeTruthy()
    expect(provider.tokenBodies[0]?.has("client_secret")).toBe(false)
    expect(provider.tokenHeaders[0]).toBeNull()
    // A definition that skipped the schema: a public client with no PKCE.
    await f.customClient(acme, "stale-client")
    await sql(f.tenant, "UPDATE items SET custom_provider=? WHERE slug='stale-client'", JSON.stringify({ ...acme, clientAuth: "none", pkce: "none" }))
    expect(await f.refused("platform.connects.start", { body: { client: "stale-client", slug: "stale", redirectUri: CALLBACK } })).toEqual({ error: "forbidden", message: "This OAuth client's provider definition is no longer accepted; add a new client." })
  })

  it("refuses a definition with an unsafe URL, a private host or too many parameters", async () => {
    const f = await subject()
    for (const bad of [{ ...acme, tokenUrl: "http://auth.acme-crm.example.com/token" }, { ...acme, tokenUrl: "https://user:pw@auth.acme-crm.example.com/token" }, { ...acme, authorizeUrl: "https://10.0.0.1/authorize" }, { ...acme, tokenUrl: "https://db.internal/token" }, { ...acme, hosts: ["localhost"] }, { ...acme, authorizeParams: Object.fromEntries(Array.from({ length: 9 }, (_, n) => [`p${n}`, "x"])) }]) {
      expect(await f.refused("platform.intakes.create", { body: { slug: "bad-client", service: { customProvider: bad } } })).toMatchObject({ error: "bad_request" })
    }
    // A stored definition the current rules refuse is never used.
    await f.customClient()
    await sql(f.tenant, "UPDATE items SET custom_provider=? WHERE slug='acme-client'", JSON.stringify({ ...acme, hosts: ["printer.local"] }))
    expect(await f.refused("platform.connects.start", { body: { client: "acme-client", slug: "acme", redirectUri: CALLBACK } })).toMatchObject({ error: "forbidden" })
  })

  it("binds the custom client's secret to the token URL's host and path, by POST", async () => {
    const f = await subject()
    await f.customClient()
    const [client] = await sql<{ binding: string }>(f.tenant, "SELECT binding FROM items WHERE slug='acme-client'")
    expect(JSON.parse(client!.binding)).toEqual(customClientBinding(acme))
  })

  it("keeps the definition fixed: no platform, device or workload operation changes it", async () => {
    const f = await subject()
    await f.customClient()
    const provider = acmeProvider()
    await f.finish(provider.consent((await f.start({ client: "acme-client", slug: "acme" })).authorizeUrl))
    const stored = await f.customProvider("acme-client")
    expect(stored).not.toBeNull()
    // A rotation with another definition is refused; one with the same keeps it.
    expect(await f.refused("platform.intakes.create", { body: { slug: "acme-client", service: { customProvider: { ...acme, hosts: ["api.attacker.example.com"] } } } })).toMatchObject({ error: "conflict" })
    await f.intake("acme-client", { customProvider: acme }, { client_secret: "acme-client-secret-rotated" })
    expect(await f.customProvider("acme-client")).toBe(stored)
    // No operation that edits an item is open to the platform.
    for (const op of ["items.update", "items.rehome", "intake.submit", "intake.createByMember", "oauth.connectCreateByMember"]) {
      expect(await f.refused(op, { slug: "acme-client", change: { binding: { hosts: ["api.attacker.example.com"] } } })).toMatchObject({ error: "forbidden" })
    }
    // Nor to a device or its workload.
    const machine = await f.device()
    const task = await f.workload(machine)
    for (const signer of [machine, task]) {
      expect((await signed(f.tenant, signer, "/v1/intakes", { kind: "oauth-client", slug: "acme-client", reason: "rotate", binding: { hosts: ["api.attacker.example.com"] } })).status).toBeGreaterThanOrEqual(400)
      expect((await signed(f.tenant, signer, "/v1/connect", { provider: "google-gmail", client: "acme-client", slug: "acme", home: "workspace", reason: "reconnect" })).status).toBe(403)
    }
    // Reconnecting with another client is refused, and with the same one keeps the definition.
    await f.customClient({ ...acme, hosts: ["api.elsewhere.example.com"] }, "other-client")
    expect(await f.refused("platform.connects.start", { body: { client: "other-client", slug: "acme", redirectUri: CALLBACK } })).toMatchObject({ error: "conflict" })
    await f.finish(provider.consent((await f.start({ client: "acme-client", slug: "acme" })).authorizeUrl))
    expect(await f.customProvider("acme-client")).toBe(stored)
    expect(await inAccess(f.tenant, (ctx) => checkedCredential(ctx, "acme")?.binding)).toEqual({ hosts: ["api.acme-crm.example.com"] })
    const client = await inAccess(f.tenant, (ctx) => checkedCredential(ctx, "acme-client")!)
    expect(await inAccess(f.tenant, (ctx) => customProviderOf(ctx, client.id))).toEqual(acme)
  })
})

describe("managed workspaces", () => {
  it("refuse a device's POST /v1/connect", async () => {
    const f = await subject()
    await f.googleClient()
    const machine = await f.device()
    const task = await f.workload(machine)
    const answer = await json<{ error: string; message: string }>(await signed(f.tenant, task, "/v1/connect", { provider: "google-gmail", slug: "gmail", home: "workspace", reason: "read my mail" }), 403)
    expect(answer).toEqual({ error: "forbidden", message: "In a managed workspace the platform starts connections." })
    expect(await sql(f.tenant, "SELECT * FROM workspace_credential_requests WHERE kind='connect'")).toEqual([])
  })

  it("admit the platform's connect operations to platform auth alone", async () => {
    const f = await subject()
    const machine = await f.device()
    const task = await f.workload(machine)
    // A device or workload cannot name a platform operation at all.
    expect((await signed(f.tenant, task, "/v1/connect/con_abc/cancel", {})).status).toBe(404)
    for (const name of platformOAuthRoutes) {
      const spec = AREAS.map((area) => area.workspaceOps?.[`platform.${name}`]).find((op) => op !== undefined)
      expect(spec?.auth).toEqual(["platform"])
    }
  })
})

it("leaves a subject without a managed workspace unreached", async () => {
  const f = await subject()
  expect(await refused(invokeAs(freshTenant(), "platform.connects.start", { body: { provider: "google-gmail", slug: "gmail", redirectUri: CALLBACK } }, platformAuth(SUBJECT)))).toMatchObject({ error: "not_found" })
  expect(f.tenant).toMatch(/^tn_/)
})
