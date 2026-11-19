import { expect, spyOn, test } from "bun:test"
import { generateSealKeyPair } from "@mehen/protocol/seal"
import { sealFields } from "../../../packages/client/src/seal.ts"
import { APPROVAL, FakePlatformVault, INTAKE, ORIGIN, PLATFORM, PLATFORM_KEY, SUBJECT } from "../../../packages/client/test/fake-platform-vault.ts"
import { GUIDE, allSamples, declaredNames, needsPlatformClient, prelude, runSamples, runnable, samplesOf, typecheckSamples } from "./samples.ts"

test("samples are the ts blocks, each with the line its code starts on", () => {
  const markdown = "# T\n\n```ts\nconst a = 1\n```\n\n```text\nnot code\n```\n\n```ts\nconst b = a\n```\n"
  expect(samplesOf(markdown, "x.md")).toEqual([
    { file: "x.md", line: 4, code: "const a = 1" },
    { file: "x.md", line: 12, code: "const b = a" },
  ])
})

test("a block gets the page's shared names it uses, unless it makes them itself", () => {
  const file = "packages/client/README.md"
  expect(prelude({ file, line: 1, code: "await forTask.relay(request)" })).toEqual(['declare const forTask: import("@mehen/client").MehenClient', 'declare const request: import("@mehen/client").RelayInput'])
  expect(prelude({ file, line: 1, code: "const forTask = createClient(options)\nawait forTask.me()" })).toEqual([])
  expect(prelude({ file, line: 1, code: 'import { status } from "x"\nstatus' })).toEqual([])
})

test("a sample that does not typecheck is reported at its line in the markdown", async () => {
  const problems = await typecheckSamples([{ file: "x.md", line: 10, code: 'const n: number = 1\nconst s: string = n\nimport { createClient } from "@mehen/client"\ncreateClient' }])
  expect(problems).toHaveLength(1)
  expect(problems[0]).toMatchObject({ file: "x.md", line: 11 })
  expect(problems[0]?.message).toContain("TS2322")
}, 60_000)

test("the samples that need no platform client typecheck as written", async () => {
  const samples = (await allSamples()).filter((s) => !needsPlatformClient(s))
  expect(samples.length).toBeGreaterThan(5)
  expect(await typecheckSamples(samples)).toEqual([])
}, 60_000)

test("the platform guide's and the client README's platform samples typecheck as written", async () => {
  const samples = (await allSamples()).filter(needsPlatformClient)
  expect(samples.length).toBeGreaterThan(5)
  expect(await typecheckSamples(samples)).toEqual([])
}, 60_000)

test("a block hands on the names it makes at its top level, destructured ones too", () => {
  expect(declaredNames('const a = 1\nlet { b, c: d } = x\nconst [e] = y\n  const inner = 2\n// const comment = 3')).toEqual(["a", "b", "d", "e"])
})

// A stand-in vault that checks every platform proof with the protocol's
// verifier and every path, query and body with the route's own schemas,
// with the platform's key registered as the operator would.
async function standIn() {
  const sealPair = await generateSealKeyPair()
  const sealJwk = (await crypto.subtle.exportKey("jwk", sealPair.publicKey)) as JsonWebKey
  const sealKey = { kty: "EC" as const, crv: "P-256" as const, x: String(sealJwk.x), y: String(sealJwk.y) }
  const vault = new FakePlatformVault(sealKey)
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey)
  vault.keys.set(PLATFORM_KEY, { platform: PLATFORM, jwk: { kty: "EC", crv: "P-256", x: String(publicJwk.x), y: String(publicJwk.y) } })
  const privateJwk = JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey))
  const sealed = await sealFields({ jwk: sealKey, kid: "seal" }, INTAKE, { key: "sk-not-real" })
  return { vault, privateJwk, sealed }
}

// The samples call the global fetch, as a reader's server would; for the run it is the stand-in's.
async function runAgainst(vault: FakePlatformVault, samples: Parameters<typeof runSamples>[0], seeds: Record<string, unknown>) {
  const standInFetch = async (input: string | URL | Request, init?: RequestInit) => vault.fetch(new Request(input, init))
  const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(Object.assign(standInFetch, { preconnect: globalThis.fetch.preconnect }))
  try {
    return await runSamples(samples, seeds, ORIGIN)
  } finally {
    fetchSpy.mockRestore()
  }
}

test("the platform guide's samples run as written, in order, against a stand-in vault", async () => {
  const { vault, privateJwk } = await standIn()
  const samples = (await allSamples()).filter((s) => s.file === GUIDE)
  expect(samples.every(runnable)).toBe(true)
  const callbackUrl = new URL(`https://app.example.com/oauth/callback?state=${"s".repeat(32)}&code=the-code`)
  const env = { PLATFORM_ID: PLATFORM, PLATFORM_KEY_ID: PLATFORM_KEY, PLATFORM_PRIVATE_JWK: privateJwk, VAULT_URL: ORIGIN }
  const scope = await runAgainst(vault, samples, { env, subject: SUBJECT, callbackUrl, approvalId: APPROVAL })
  expect(Object.keys(scope)).toEqual(expect.arrayContaining(["view", "user", "device", "sealed", "item", "started", "finished", "acme", "decided", "project", "page", "gone"]))
  expect(vault.seen.map((s) => s.route.name)).toEqual([
    "platform.view",
    "subjects.ensure",
    "devices.create",
    "intakes.create",
    "intakes.submit",
    "intakes.create",
    "intakes.submit",
    "connects.start",
    "connects.finish",
    "intakes.create",
    "connects.start",
    "approvals.get",
    "approvals.decide",
    "projects.create",
    "projects.setVar",
    "projects.setVar",
    "defaults.put",
    "audit.read",
    "workspace.freeze",
    "subjects.remove",
  ])
}, 60_000)

test("the client README's platform samples run as written, in order, against a stand-in vault", async () => {
  const { vault, privateJwk, sealed } = await standIn()
  const samples = (await allSamples()).filter((s) => s.file !== GUIDE && runnable(s))
  expect(samples.length).toBeGreaterThan(5)
  await runAgainst(vault, samples, { privateJwkText: privateJwk, platformId: PLATFORM, keyId: PLATFORM_KEY, approvalId: APPROVAL, sealed })
  expect(vault.seen.map((s) => s.route.name)).toEqual(["platform.view", "subjects.ensure", "devices.create", "intakes.create", "intakes.submit", "approvals.get", "approvals.decide", "projects.create", "projects.setVar", "subjects.remove"])
}, 60_000)
