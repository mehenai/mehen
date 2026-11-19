import { describe, expect, it } from "bun:test"
import { PLATFORM_ROUTES, platformPathSubject } from "@mehen/protocol/platform"
import { PROOF_HEADER } from "@mehen/protocol/proof"
import { generateSealKeyPair, openText } from "@mehen/protocol/seal"
import { MehenRefusal, MehenTransport, type PlatformClient, createPlatformClient, generateKey, platformSigner } from "../src/index.ts"
import { sealFields } from "../src/seal.ts"
import { APPROVAL, CONNECT, DIGEST, FakePlatformVault, INTAKE, ITEM, ORIGIN, PLATFORM, PLATFORM_KEY, PROJECT, SUBJECT, fixtureAnswers, json, refuse } from "./fake-platform-vault.ts"

async function setup(options: { userAgent?: string } = {}) {
  const seal = await generateSealKeyPair()
  const sealJwk = (await crypto.subtle.exportKey("jwk", seal.publicKey)) as JsonWebKey
  const vault = new FakePlatformVault({ kty: "EC", crv: "P-256", x: String(sealJwk.x), y: String(sealJwk.y) })
  const key = await generateKey()
  vault.keys.set(PLATFORM_KEY, { platform: PLATFORM, jwk: key.jwk })
  const platform = createPlatformClient({ vaultUrl: ORIGIN, signer: platformSigner(PLATFORM, PLATFORM_KEY, key.privateKey), fetch: vault.fetch, ...options })
  return { vault, key, platform, seal }
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection")
    },
    (error: unknown) => error,
  )
}

// Every client method once, in an order a platform would use them.
async function everyCall(platform: PlatformClient): Promise<void> {
  await platform.view()
  await platform.defaults.get()
  await platform.defaults.put({ scopes: { "google-gmail": ["https://www.googleapis.com/auth/gmail.readonly"] }, tags: ["globex"], customReads: "approve", rules: {} })
  await platform.subjects.ensure(SUBJECT)
  await platform.subjects.get(SUBJECT)
  await platform.subjects.list()
  const jim = platform.subject(SUBJECT)
  const agent = await generateKey()
  await jim.devices.create({ name: "agent-1", jwk: agent.jwk, modes: ["relay", "placeholder"], label: "agent:1" })
  await jim.devices.list()
  await jim.devices.revoke("dev_agent0001")
  await jim.items.list()
  await jim.items.remove("openai")
  await jim.intakes.create({ slug: "google-oauth-client", service: { template: "google-oauth-client" } })
  await jim.intakes.submit(INTAKE, { sealed: { client_secret: { v: 1, epk: { kty: "EC", crv: "P-256", x: "x".repeat(43), y: "y".repeat(43) }, iv: "i".repeat(16), ct: "c" } }, publicFields: { client_id: "jims-client" } })
  await jim.intakes.cancel(INTAKE)
  await jim.connects.start({ provider: "google-gmail", slug: "gmail", redirectUri: "https://app.globex.ai/oauth/callback" })
  await jim.connects.finish({ state: "s".repeat(32), code: "the-code" })
  await jim.connects.status(CONNECT)
  await jim.connects.cancel(CONNECT)
  await jim.approvals.list()
  await jim.approvals.get(APPROVAL)
  await jim.approvals.decide(APPROVAL, { decision: "approve", digest: DIGEST, ttlSeconds: 300, ref: "card:42" })
  await jim.projects.create({ slug: "agent-one", environments: [{ name: "computers" }], defaultEnv: "computers" })
  await jim.projects.get(PROJECT)
  await jim.projects.setVar(PROJECT, "REGION", { env: "computers", before: null, plain: "eu" })
  await jim.projects.remove(PROJECT)
  await jim.audit()
  await jim.freeze()
  await jim.unfreeze()
  await platform.subjects.remove(SUBJECT)
  await platform.subjects.removeAll("globex")
}

describe("createPlatformClient", () => {
  it("calls every platform route, each signed with a platform proof the protocol's verifier accepts", async () => {
    const { vault, platform } = await setup({ userAgent: "globex-broker/1" })
    await everyCall(platform)
    const called = new Set(vault.seen.map((seen) => seen.route.name))
    expect([...called].sort()).toEqual(PLATFORM_ROUTES.map((route) => route.name).sort())
    for (const seen of vault.seen) {
      expect(seen.headers.has(PROOF_HEADER)).toBe(false)
      expect(seen.headers.get("user-agent")).toMatch(/^mehen-client\/\d+\.\d+\.\d+ globex-broker\/1$/)
      expect(seen.claims.plt).toBe(PLATFORM)
      expect(seen.claims.htm).toBe(seen.route.method)
      expect(seen.claims.htu).toBe(seen.url)
      expect(seen.claims.sub ?? null).toBe(platformPathSubject(seen.path))
    }
    expect(new Set(vault.seen.map((seen) => seen.claims.jti)).size).toBe(vault.seen.length)
  })

  it("parses every fixture with its row's answer schema", async () => {
    const { seal } = await setup()
    const jwk = (await crypto.subtle.exportKey("jwk", seal.publicKey)) as JsonWebKey
    const answers = fixtureAnswers({ kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y) })
    for (const route of PLATFORM_ROUTES) expect(route.answer.safeParse(answers[route.name]).success, route.name).toBe(true)
  })

  it("sends bodies, queries and methods as each row says", async () => {
    const { vault, platform } = await setup()
    const jim = platform.subject(SUBJECT)

    await platform.subjects.ensure(SUBJECT)
    expect([vault.last.method, vault.last.path, vault.last.body]).toEqual(["PUT", `/v1/platform/subjects/${SUBJECT}`, "{}"])
    await platform.subjects.remove(SUBJECT)
    expect([vault.last.method, vault.last.body]).toEqual(["DELETE", "{}"])
    await jim.devices.revoke("dev_agent0001")
    expect([vault.last.method, vault.last.path, vault.last.body]).toEqual(["DELETE", `/v1/platform/subjects/${SUBJECT}/devices/dev_agent0001`, ""])
    expect(vault.last.headers.has("content-type")).toBe(false)
    await platform.subjects.removeAll("globex")
    expect([vault.last.method, vault.last.path, vault.last.json]).toEqual(["DELETE", "/v1/platform/subjects", { confirm: "globex" }])
    expect(vault.last.claims.sub).toBeUndefined()

    await platform.subjects.list()
    expect(vault.last.search).toBe("")
    await platform.subjects.list("page-2")
    expect(vault.last.search).toBe("?cursor=page-2")
    await jim.items.list({ kind: "api-key", tag: "globex" })
    expect(vault.last.search).toBe("?kind=api-key&tag=globex")
    await jim.approvals.list({ status: "pending" })
    expect(vault.last.search).toBe("?status=pending")
    await jim.audit({ cursor: "41", limit: 50 })
    expect(vault.last.search).toBe("?cursor=41&limit=50")
    expect(vault.last.claims.htu).toBe(`${ORIGIN}/v1/platform/subjects/${SUBJECT}/audit?cursor=41&limit=50`)

    await jim.projects.setVar(PROJECT, "OPENAI_API_KEY", { env: "computers", before: { plain: "old" }, item: "openai", field: "key" })
    expect([vault.last.method, vault.last.path]).toEqual(["PUT", `/v1/platform/subjects/${SUBJECT}/projects/${PROJECT}/vars/OPENAI_API_KEY`])
    expect(vault.last.json).toEqual({ env: "computers", before: { plain: "old" }, item: "openai", field: "key" })

    await jim.approvals.decide(APPROVAL, { decision: "deny", digest: DIGEST })
    expect(vault.last.json).toEqual({ decision: "deny", digest: DIGEST })

    // The subject's own OAuth app: a catalogue client template, or a client
    // with its own provider definition, then a connect naming that client.
    await jim.intakes.create({ slug: "google-oauth-client", service: { template: "google-oauth-client" } })
    expect(vault.last.json).toEqual({ slug: "google-oauth-client", service: { template: "google-oauth-client" } })
    const customProvider = { name: "Example", authorizeUrl: "https://auth.example.com/authorize", tokenUrl: "https://auth.example.com/token", scopes: ["read"], pkce: "S256" as const, clientAuth: "client_secret_basic" as const, hosts: ["api.example.com"] }
    await jim.intakes.create({ slug: "example-client", service: { customProvider } })
    expect(vault.last.json).toEqual({ slug: "example-client", service: { customProvider } })
    await jim.connects.start({ client: "example-client", slug: "example", redirectUri: "https://app.globex.ai/oauth/callback" })
    expect(vault.last.json).toEqual({ client: "example-client", slug: "example", redirectUri: "https://app.globex.ai/oauth/callback" })
    await expect(jim.intakes.create({ slug: "bad-client", service: { customProvider: { ...customProvider, tokenUrl: "https://10.0.0.1/token" } } })).rejects.toBeInstanceOf(TypeError)
  })

  it("answers each method with its row's answer, unwrapped where the client says", async () => {
    const { vault, platform } = await setup()
    const jim = platform.subject(SUBJECT)
    expect(await platform.defaults.get()).toEqual({ defaults: { scopes: {}, tags: [], customReads: "approve", rules: {} }, defaultsRevision: 3 })
    expect(vault.last.route.name).toBe("platform.view")
    expect((await jim.items.list())[0]?.slug).toBe(ITEM.slug)
    expect((await jim.devices.list())[0]?.liveWorkloads).toBe(0)
    expect((await jim.approvals.list())[0]?.approval).toBe(APPROVAL)
    expect(await jim.intakes.cancel(INTAKE)).toBeUndefined()
    expect(await jim.freeze()).toBeUndefined()
    const decided = await jim.approvals.decide(APPROVAL, { decision: "approve", digest: DIGEST, ref: "card:42" })
    expect(decided.decidedBy).toEqual({ platform: PLATFORM, key: PLATFORM_KEY, ref: "card:42" })
  })

  it("reads subjects.ensure's 201 and 200 alike", async () => {
    const { vault, platform } = await setup()
    const view = { subject: SUBJECT, status: "active" as const, createdAt: "2026-10-29T10:00:00.000Z", counts: { devices: 0, items: 0, projects: 0 } }
    vault.on("subjects.ensure", () => json(view, 201))
    expect(await platform.subjects.ensure(SUBJECT)).toEqual(view)
    vault.on("subjects.ensure", () => json(view, 200))
    expect(await platform.subjects.ensure(SUBJECT)).toEqual(view)
  })

  it("reads projects.create's 201 for a new project and 200 for the same one again alike", async () => {
    const { vault, platform } = await setup()
    const view = { id: "prj_agentone1", slug: "agent-one", defaultEnv: "computers", environments: [{ name: "computers" }], vars: [] }
    const jim = platform.subject(SUBJECT)
    const input = { slug: "agent-one", environments: [{ name: "computers" }], defaultEnv: "computers" }
    vault.on("projects.create", () => json(view, 201))
    expect(await jim.projects.create(input)).toEqual(view)
    vault.on("projects.create", () => json(view, 200))
    expect(await jim.projects.create(input)).toEqual(view)
  })

  it("refuses input the row's schemas refuse, before anything is signed or sent", async () => {
    const { vault, platform } = await setup()
    expect(() => platform.subject("short")).toThrow(TypeError)
    expect(() => platform.subject("has/slash-in-it")).toThrow(TypeError)
    await expect(platform.subjects.get("../platform")).rejects.toBeInstanceOf(TypeError)
    const jim = platform.subject(SUBJECT)
    const agent = await generateKey()
    const refused: Promise<unknown>[] = [
      jim.devices.revoke("../../platform"),
      jim.devices.create({ name: "agent-1", jwk: agent.jwk, modes: ["relay", "lease" as "relay"] }),
      jim.items.remove("Not A Slug"),
      jim.approvals.get("apr_../x"),
      jim.approvals.decide(APPROVAL, { decision: "approve", digest: "short" }),
      jim.approvals.decide(APPROVAL, { decision: "approve", digest: DIGEST, ttlSeconds: 3600 }),
      jim.projects.setVar(PROJECT, "NOT-A-NAME", { env: "computers", before: null }),
      jim.projects.setVar(PROJECT, "REGION", { env: "computers", before: null, plain: "eu", item: "openai" }),
      jim.audit({ limit: 1000 }),
      jim.intakes.submit(INTAKE, { sealed: {} }),
      jim.connects.finish({ state: "s".repeat(32), code: "c", error: "access_denied" }),
      jim.connects.start({ provider: "google-gmail", slug: "gmail", redirectUri: "http://app.globex.ai/oauth/callback" }),
      jim.connects.start({ slug: "gmail", redirectUri: "https://app.globex.ai/oauth/callback" }),
      platform.defaults.put({ scopes: {}, tags: [], customReads: "approve", rules: { openai: [{ match: { methods: ["GET"] }, action: "allow" }] } } as never),
      platform.subjects.removeAll("Not a slug"),
    ]
    for (const promise of refused) expect(await caught(promise)).toBeInstanceOf(TypeError)
    expect(vault.seen).toHaveLength(0)
  })

  it("throws the vault's refusals as MehenRefusal with their codes", async () => {
    const { vault, platform } = await setup()
    vault.on("subjects.ensure", () => refuse("quota_exceeded", "That is past this platform's limit."))
    vault.on("platform.view", () => refuse("platform_suspended", "This platform is suspended."))
    vault.on("approvals.decide", () => refuse("conflict", "The request changed; ask again."))
    const quota = (await caught(platform.subjects.ensure(SUBJECT))) as MehenRefusal
    expect(quota).toBeInstanceOf(MehenRefusal)
    expect([quota.code, quota.status]).toEqual(["quota_exceeded", 403])
    const suspended = (await caught(platform.view())) as MehenRefusal
    expect([suspended.code, suspended.status, suspended.message]).toEqual(["platform_suspended", 403, "This platform is suspended."])
    const conflict = (await caught(platform.subject(SUBJECT).approvals.decide(APPROVAL, { decision: "approve", digest: DIGEST }))) as MehenRefusal
    expect(conflict.code).toBe("conflict")
    expect(conflict.link).toBeUndefined()
  })

  it("treats an answer that is not its row's shape as a MehenTransport", async () => {
    const { vault, platform } = await setup()
    vault.on("subjects.get", () => json({ subject: SUBJECT, status: "lost" }))
    vault.on("connects.start", () => json({ connect: CONNECT, authorizeUrl: "http://accounts.example/auth", expiresAt: "2026-10-29T10:15:00.000Z" }, 201))
    vault.on("platform.view", () => new Response("<html>gateway</html>", { status: 502 }))
    expect(await caught(platform.subjects.get(SUBJECT))).toBeInstanceOf(MehenTransport)
    expect(await caught(platform.subject(SUBJECT).connects.start({ provider: "google-gmail", slug: "gmail", redirectUri: "https://app.globex.ai/oauth/callback" }))).toBeInstanceOf(MehenTransport)
    expect(await caught(platform.view())).toBeInstanceOf(MehenTransport)
  })

  it("is refused by the vault when the proof is not the platform's own", async () => {
    const { vault, key } = await setup()
    const other = await generateKey()
    const unknownKey = createPlatformClient({ vaultUrl: ORIGIN, signer: platformSigner(PLATFORM, "pky_unknown01", key.privateKey), fetch: vault.fetch })
    expect(((await caught(unknownKey.view())) as MehenRefusal).code).toBe("unauthenticated")
    const otherPlatform = createPlatformClient({ vaultUrl: ORIGIN, signer: platformSigner("plt_other0001", PLATFORM_KEY, key.privateKey), fetch: vault.fetch })
    expect(((await caught(otherPlatform.view())) as MehenRefusal).code).toBe("unauthenticated")
    const wrongKey = createPlatformClient({ vaultUrl: ORIGIN, signer: platformSigner(PLATFORM, PLATFORM_KEY, other.privateKey), fetch: vault.fetch })
    expect(((await caught(wrongKey.view())) as MehenRefusal).message).toContain("(signature)")
    // A request altered on the way: another subject's path, or another body.
    const tamper = (change: (request: Request) => Promise<Request>) => createPlatformClient({ vaultUrl: ORIGIN, signer: platformSigner(PLATFORM, PLATFORM_KEY, key.privateKey), fetch: async (request) => vault.fetch(await change(request)) })
    const otherSubject = tamper(async (request) => new Request(request.url.replace(SUBJECT, "globex_subject0002"), { method: request.method, headers: request.headers }))
    expect(((await caught(otherSubject.subjects.get(SUBJECT))) as MehenRefusal).code).toBe("proof_invalid")
    const otherBody = tamper(async (request) => new Request(request.url, { method: request.method, headers: request.headers, body: JSON.stringify({ confirm: "other" }) }))
    expect(((await caught(otherBody.subjects.removeAll("globex"))) as MehenRefusal).message).toContain("(body)")
    expect(vault.seen).toHaveLength(0)
  })

  it("never replays a proof: each call is signed afresh", async () => {
    const { vault, platform, key } = await setup()
    let first: Request | null = null
    const recording = createPlatformClient({ vaultUrl: ORIGIN, signer: platformSigner(PLATFORM, PLATFORM_KEY, key.privateKey), fetch: async (request) => {
      first ??= request.clone()
      return vault.fetch(request)
    } })
    await recording.view()
    await platform.view()
    const replayed = first as Request | null
    if (replayed === null) throw new Error("no request recorded")
    const answer = await vault.fetch(replayed)
    expect(await answer.json()).toMatchObject({ error: "proof_invalid", message: "This Mehen-Proof has already been used." })
  })
})

describe("platformSigner", () => {
  it("checks the platform and key ids, as createPlatformClient does for any signer", async () => {
    const { privateKey } = await generateKey()
    expect(() => platformSigner("globex", PLATFORM_KEY, privateKey)).toThrow(TypeError)
    expect(() => platformSigner(PLATFORM, "dev_device0001", privateKey)).toThrow(TypeError)
    const sign = async () => new Uint8Array(64)
    expect(() => createPlatformClient({ vaultUrl: ORIGIN, signer: { platformId: PLATFORM, keyId: "key", sign } })).toThrow(TypeError)
    expect(() => createPlatformClient({ vaultUrl: "http://vault.example", signer: { platformId: PLATFORM, keyId: PLATFORM_KEY, sign } })).toThrow(TypeError)
  })
})

describe("a key typed into a platform's page", () => {
  it("is sealed with @mehen/client/seal, submitted by the platform, and opens only in the vault", async () => {
    const { vault, platform, seal } = await setup()
    const jim = platform.subject(SUBJECT)
    const opened: string[] = []
    vault.on("intakes.submit", async (seen) => {
      const { sealed } = seen.json as { sealed: Record<string, Parameters<typeof openText>[1]> }
      for (const [field, box] of Object.entries(sealed)) opened.push(await openText(seal.privateKey, box, `intake/${seen.params.intake}/${field}`))
      return json({ item: ITEM })
    })
    const intake = await jim.intakes.create({ slug: "openai", service: { template: "openai" } })
    const boxes = await sealFields(intake.sealKey, intake.intake, { key: "sk-proj-not-a-real-key" })
    const item = await jim.intakes.submit(intake.intake, { sealed: boxes })
    expect(item.slug).toBe("openai")
    expect(opened).toEqual(["sk-proj-not-a-real-key"])
    expect(vault.last.body).not.toContain("sk-proj-not-a-real-key")
  })
})
