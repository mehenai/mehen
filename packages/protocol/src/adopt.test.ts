import { describe, expect, test } from "bun:test"
import {
  ADOPTION_ID,
  ADOPTION_LIMITS,
  ADOPTION_REF,
  AdoptionApprove,
  type AdoptionCompareView,
  AdoptionCreate,
  AdoptionDecision,
  type AdoptionDecisionInput,
  AdoptionIndex,
  type AdoptionIndexInput,
  AdoptionItemUpload,
  type AdoptionItemUploadInput,
  AdoptionKeepOpen,
  AdoptionStatusSchema,
  AdoptionUpload,
  type WorkspaceAdoptionItemView,
  adoptionDigest,
  adoptionDigestInput,
  adoptionRepoints,
  adoptionSealContext,
} from "./adopt.ts"
import { canonicalJson } from "./canonical-json.ts"
import { sha256B64 } from "./bytes.ts"
import { generateSealKeyPair, openText, seal } from "./seal.ts"

const ADP = "adp_k2m9q4"

describe("ids and refs", () => {
  test("an adoption id is adp_ and up to 60 id characters", () => {
    for (const ok of ["adp_a", "adp_K2m9-q4_x", `adp_${"a".repeat(60)}`]) expect(ADOPTION_ID.test(ok), ok).toBe(true)
    for (const bad of ["adp_", "int_k2m9q4", "adp_a/b", "adp_a b", `adp_${"a".repeat(61)}`, " adp_a"]) expect(ADOPTION_ID.test(bad), bad).toBe(false)
  })

  test("a ref is a and 3 to 7 lower-case letters or digits", () => {
    for (const ok of ["a001", "a0z9", "abcdefgh"]) expect(ADOPTION_REF.test(ok), ok).toBe(true)
    for (const bad of ["a01", "b001", "A001", "a00X", "abcdefghi", "a-01", "a001 "]) expect(ADOPTION_REF.test(bad), bad).toBe(false)
  })
})

describe("adoption context binds adoption, ref and field", () => {
  test("the context names all three under adopt/", () => {
    expect(adoptionSealContext(ADP, "a001", "key")).toBe(`adopt/${ADP}/a001/key`)
  })

  test("a box opens only under the context it was sealed for", async () => {
    const pair = await generateSealKeyPair()
    const box = await seal(pair.publicKey, "sk-proj-adopted-value", adoptionSealContext(ADP, "a001", "key"))
    expect(await openText(pair.privateKey, box, adoptionSealContext(ADP, "a001", "key"))).toBe("sk-proj-adopted-value")
    for (const other of [
      adoptionSealContext(ADP, "a002", "key"),
      adoptionSealContext(ADP, "a001", "token"),
      adoptionSealContext("adp_other", "a001", "key"),
      `intake/${ADP}/key`,
      "intake/int_abc/key",
    ]) {
      await expect(openText(pair.privateKey, box, other)).rejects.toThrow("sealed box failed authentication")
    }
  })
})

describe("limits", () => {
  test("a chunk fits under the vault's 1 000 000 byte body limit, and a batch lives as long as an intake", () => {
    expect(ADOPTION_LIMITS.maxChunkBytes).toBeLessThan(1_000_000)
    expect<number>(ADOPTION_LIMITS.ttlMs).toBe(24 * 3_600_000)
    expect(ADOPTION_LIMITS.maxItems).toBe(500)
    expect(ADOPTION_LIMITS.maxMachines).toBe(8)
    expect(ADOPTION_LIMITS.maxStagedBytes).toBe(8_000_000)
    expect(ADOPTION_LIMITS.maxOpenPerMember).toBe(3)
  })

  test("a compare row is one per target per batch and ten per target a day, and a batch kept open lives at most 7 days", () => {
    const DAY = 86_400_000
    expect(ADOPTION_LIMITS.maxComparesPerTarget).toBe(1)
    expect(ADOPTION_LIMITS.maxComparesPerTargetPerDay).toBe(10)
    expect(ADOPTION_LIMITS.keepOpenMs).toBe(3 * DAY)
    expect(ADOPTION_LIMITS.maxLifeMs).toBe(7 * DAY)
    // Kept open twice, a batch reaches its 7 days exactly.
    expect(ADOPTION_LIMITS.ttlMs + 2 * ADOPTION_LIMITS.keepOpenMs).toBe(ADOPTION_LIMITS.maxLifeMs)
    expect(ADOPTION_LIMITS.replacedKeptMs).toBe(30 * DAY)
    expect(ADOPTION_LIMITS.indexKeptMs).toBe(30 * DAY)
    expect<number>(ADOPTION_LIMITS.maxIndexItems).toBe(4 * ADOPTION_LIMITS.maxItems)
  })
})

const box = { v: 1 as const, epk: { kty: "EC" as const, crv: "P-256" as const, x: "x".repeat(43), y: "y".repeat(43) }, iv: "i".repeat(16), ct: "c".repeat(40) }

function upload(overrides: Partial<AdoptionItemUploadInput> = {}): AdoptionItemUploadInput {
  return {
    ref: "a001",
    slug: "openai-billing-api-dev",
    kind: "api-key",
    provider: "openai",
    binding: null,
    injection: null,
    home: { kind: "project", project: "prj_billing" },
    tags: ["adopted"],
    publicFields: {},
    sealed: { key: box },
    sources: [{ path: "/Users/sam/code/billing-api/.env", variable: "OPENAI_API_KEY", stale: [] }],
    repo: { remote: "github.com/acme/billing-api", env: "dev" },
    ...overrides,
  }
}

describe("device schemas", () => {
  test("create takes a machine and the expected count, and nothing else", () => {
    expect(AdoptionCreate.parse({ machine: "sam-mac-mini", expectedItems: 212 })).toEqual({ machine: "sam-mac-mini", expectedItems: 212 })
    expect(AdoptionCreate.parse({ machine: "m", reason: "Adopting .env files", session: "claude", expectedItems: 1 })).toMatchObject({ reason: "Adopting .env files" })
    for (const bad of [
      { machine: "", expectedItems: 1 },
      { machine: "m", expectedItems: 0 },
      { machine: "m", expectedItems: ADOPTION_LIMITS.maxItems + 1 },
      { machine: "m".repeat(65), expectedItems: 1 },
      { machine: "m", expectedItems: 1, sealKey: "mine" },
    ]) expect(AdoptionCreate.safeParse(bad).success, JSON.stringify(bad)).toBe(false)
  })

  test("an item upload accepts a template item and a custom one", () => {
    expect(AdoptionItemUpload.parse(upload())).toEqual(upload())
    const custom = upload({
      ref: "a002",
      slug: "billing-db-dev",
      kind: "database-url",
      provider: null,
      binding: { hosts: ["db.internal.example"] },
      sealed: { url: box },
      home: { kind: "member", member: "mem_alex" },
      repo: null,
      sources: [{ path: "/Users/sam/.config/app/settings.json", pointer: "/env/DATABASE_URL", stale: ["mtime"] }],
    })
    expect(AdoptionItemUpload.parse(custom)).toEqual(custom)
    expect(AdoptionUpload.parse({ items: [upload(), custom] }).items).toHaveLength(2)
  })

  test("an upload from a CLI older than compare rows parses with neither compare nor mtime", () => {
    const parsed = AdoptionItemUpload.parse(upload())
    expect(parsed).not.toHaveProperty("compare")
    expect(parsed.sources[0]).not.toHaveProperty("mtime")
  })

  test("an item upload may ask to be compared and say when each source last changed", () => {
    const compared = upload({ compare: true, sources: [{ path: "/Users/sam/code/billing-api/.env", variable: "OPENAI_API_KEY", stale: [], mtime: "2026-10-30T12:00:00.000Z" }] })
    expect(AdoptionItemUpload.parse(compared)).toEqual(compared)
    expect(AdoptionItemUpload.parse(upload({ compare: false }))).toEqual(upload({ compare: false }))
    for (const bad of [
      upload({ compare: "yes" as never }),
      upload({ sources: [{ path: "/a", stale: [], mtime: "yesterday" }] }),
      upload({ sources: [{ path: "/a", stale: [], mtime: 1_761_825_600_000 as never }] }),
    ]) expect(AdoptionItemUpload.safeParse(bad).success, JSON.stringify(bad).slice(0, 120)).toBe(false)
  })

  test("an item upload refuses unknown keys, bad refs and names, and too many tags or sources", () => {
    for (const bad of [
      { ...upload(), value: "sk-proj-plaintext" },
      upload({ ref: "b001" }),
      upload({ ref: "a01" }),
      upload({ slug: "Not A Slug" }),
      upload({ kind: "password" as never }),
      upload({ home: { kind: "private" } as never }),
      upload({ tags: Array.from({ length: 17 }, (_, i) => `t${i}`) }),
      upload({ sources: [] }),
      upload({ sources: Array.from({ length: 33 }, () => ({ path: "/a", stale: [] })) }),
      upload({ sources: [{ path: "/a", stale: [], value: "x" } as never] }),
      upload({ sources: [{ path: "/a", variable: "NOT-A-NAME", stale: [] }] }),
      upload({ repo: { remote: null, env: "Prod" } }),
      upload({ sealed: { key: { ...box, ct: "c".repeat(200_001) } } }),
    ]) expect(AdoptionItemUpload.safeParse(bad).success, JSON.stringify(bad).slice(0, 120)).toBe(false)
  })

  test("an upload chunk holds 1 to 200 items and nothing else", () => {
    expect(AdoptionUpload.safeParse({ items: [] }).success).toBe(false)
    expect(AdoptionUpload.safeParse({ items: Array.from({ length: 200 }, () => upload()) }).success).toBe(true)
    expect(AdoptionUpload.safeParse({ items: Array.from({ length: 201 }, () => upload()) }).success).toBe(false)
    expect(AdoptionUpload.safeParse({ items: [upload()], adoption: ADP }).success).toBe(false)
  })
})

describe("member schemas", () => {
  test("a decision names a ref, the tick and a home", () => {
    const decision = { ref: "a001", include: true, home: { kind: "workspace" as const } }
    expect(AdoptionDecision.parse(decision)).toEqual(decision)
    expect(AdoptionDecision.safeParse({ ...decision, ref: "x001" }).success).toBe(false)
    expect(AdoptionDecision.safeParse({ ...decision, slug: "other" }).success).toBe(false)
    expect(AdoptionDecision.safeParse({ ref: "a001", include: true }).success).toBe(false)
  })

  test("a decision may name an action; only a rename takes a slug and repoints", () => {
    const decision = { ref: "a001", include: true, home: { kind: "workspace" as const } }
    const repoint = [{ project: "prj_billing", env: "dev", variable: "OPENAI_API_KEY" }]
    for (const action of ["store", "map", "replace"] as const) expect(AdoptionDecision.parse({ ...decision, action })).toEqual({ ...decision, action })
    expect(AdoptionDecision.parse({ ...decision, action: "rename", slug: "openai-billing-api-linuxbox" })).toEqual({ ...decision, action: "rename", slug: "openai-billing-api-linuxbox" })
    expect(AdoptionDecision.parse({ ...decision, action: "rename", slug: "openai-2", repoint })).toEqual({ ...decision, action: "rename", slug: "openai-2", repoint })
    for (const bad of [
      { ...decision, action: "merge" },
      { ...decision, action: "rename" },
      { ...decision, action: "rename", slug: "Not A Slug" },
      { ...decision, action: "replace", slug: "openai-2" },
      { ...decision, action: "map", repoint },
      { ...decision, repoint },
      { ...decision, action: "rename", slug: "openai-2", repoint: [{ ...repoint[0], env: "Prod" }] },
      { ...decision, action: "rename", slug: "openai-2", repoint: [{ ...repoint[0], variable: "NOT-A-NAME" }] },
      { ...decision, action: "rename", slug: "openai-2", repoint: [{ ...repoint[0], value: "x" }] },
      { ...decision, action: "rename", slug: "openai-2", repoint: Array.from({ length: 65 }, (_, i) => ({ ...repoint[0], variable: `V${i}` })) },
    ]) expect(AdoptionDecision.safeParse(bad).success, JSON.stringify(bad).slice(0, 120)).toBe(false)
  })

  test("an approval holds 1 to maxItems decisions and nothing else", () => {
    const decision = { ref: "a001", include: false, home: { kind: "workspace" } }
    expect(AdoptionApprove.safeParse({ decisions: [] }).success).toBe(false)
    expect(AdoptionApprove.safeParse({ decisions: Array.from({ length: ADOPTION_LIMITS.maxItems }, () => decision) }).success).toBe(true)
    expect(AdoptionApprove.safeParse({ decisions: Array.from({ length: ADOPTION_LIMITS.maxItems + 1 }, () => decision) }).success).toBe(false)
    expect(AdoptionApprove.safeParse({ decisions: [decision], digest: "d" }).success).toBe(false)
  })
})

function view(ref: string, overrides: Partial<WorkspaceAdoptionItemView> = {}): WorkspaceAdoptionItemView {
  return {
    ref,
    slug: `item-${ref}`,
    kind: "api-key",
    provider: "openai",
    providerName: "OpenAI API key",
    binding: { value: { hosts: ["api.openai.com"] }, verified: true },
    injection: { value: { in: "header", name: "Authorization", format: "Bearer {key}" }, verified: true },
    home: { kind: "project", project: "prj_billing" },
    homesAllowed: [{ kind: "project", project: "prj_billing" }, { kind: "workspace" }],
    tags: ["b", "a"],
    publicFields: {},
    secrets: [{ name: "key", length: 51, prefix: "sk-proj-", fingerprint: "AbC123dEf456", box: "box-digest-1" }],
    sources: [{ machine: "sam-mac-mini", path: "/Users/sam/code/billing-api/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [] }],
    sameValueAs: [],
    repo: { remote: "github.com/acme/billing-api", env: "dev" },
    problem: null,
    ...overrides,
  }
}

const ITEMS = [view("a001"), view("a002", { kind: "smtp-imap", provider: null, providerName: null, publicFields: { host: "smtp.example.com", username: "bot" }, secrets: [{ name: "password", length: 20, prefix: "", fingerprint: "ZyX987", box: "box-digest-2" }] }), view("a003")]
const DECISIONS: AdoptionDecisionInput[] = [
  { ref: "a001", include: true, home: { kind: "project", project: "prj_billing" } },
  { ref: "a002", include: true, home: { kind: "workspace" } },
  { ref: "a003", include: false, home: { kind: "workspace" } },
]

async function digestWith(items: WorkspaceAdoptionItemView[], decisions: AdoptionDecisionInput[] = DECISIONS): Promise<string> {
  return adoptionDigest(ADP, items, decisions)
}

function replace(ref: string, change: Partial<WorkspaceAdoptionItemView>): WorkspaceAdoptionItemView[] {
  return ITEMS.map((item) => (item.ref === ref ? { ...item, ...change } : item))
}

function replaceSecret(change: Partial<WorkspaceAdoptionItemView["secrets"][number]>): WorkspaceAdoptionItemView[] {
  return replace("a001", { secrets: [{ ...ITEMS[0]!.secrets[0]!, ...change }] })
}

describe("digest covers what is stored and nothing else", () => {
  test("it is base64url SHA-256 of the canonical digest input", async () => {
    expect(await digestWith(ITEMS)).toBe(await sha256B64(canonicalJson(adoptionDigestInput(ADP, ITEMS, DECISIONS))))
  })

  // A batch staged before the reconcile deploy, and a review page opened
  // before it, sign these exact bytes.
  test("a store decision hashes to the digest pages signed before actions existed", async () => {
    const BEFORE_ACTIONS = "UrbQSHTRxfBYFjtJnDs8SDdOiosTHQ_ZGQHU6cvZHQk"
    expect(await digestWith(ITEMS)).toBe(BEFORE_ACTIONS)
    expect(await digestWith(ITEMS, DECISIONS.map((d) => ({ ...d, action: "store" as const })))).toBe(BEFORE_ACTIONS)
    expect(await digestWith(ITEMS.map((item) => ({ ...item, compare: null })))).toBe(BEFORE_ACTIONS)
  })

  test("it does not depend on the order of rows, decisions, tags or secret fields", async () => {
    const base = await digestWith(ITEMS)
    expect(await digestWith([...ITEMS].reverse())).toBe(base)
    expect(await digestWith(ITEMS, [...DECISIONS].reverse())).toBe(base)
    expect(await digestWith(replace("a001", { tags: ["a", "b"] }))).toBe(base)
    const twoFields = replace("a002", { secrets: [{ name: "password", length: 20, prefix: "", fingerprint: "ZyX987", box: "box-digest-2" }, { name: "api_token", length: 9, prefix: "", fingerprint: "Q", box: "box-3" }] })
    const swapped = replace("a002", { secrets: [...twoFields[1]!.secrets].reverse() })
    expect(await digestWith(swapped)).toBe(await digestWith(twoFields))
  })

  test("it changes when anything signed changes", async () => {
    const base = await digestWith(ITEMS)
    const changed: [string, Promise<string>][] = [
      ["adoption", adoptionDigest("adp_other", ITEMS, DECISIONS)],
      ["slug", digestWith(replace("a001", { slug: "openai-other" }))],
      ["kind", digestWith(replace("a001", { kind: "bearer-token" }))],
      ["provider", digestWith(replace("a001", { provider: "anthropic" }))],
      ["binding", digestWith(replace("a001", { binding: { value: { hosts: ["evil.example"] }, verified: false } }))],
      ["injection", digestWith(replace("a001", { injection: { value: null, verified: false } }))],
      ["home", digestWith(ITEMS, DECISIONS.map((d) => (d.ref === "a001" ? { ...d, home: { kind: "workspace" } } : d)))],
      ["tags", digestWith(replace("a001", { tags: ["a"] }))],
      ["public field", digestWith(replace("a002", { publicFields: { host: "smtp.evil.example", username: "bot" } }))],
      ["secret length", digestWith(replaceSecret({ length: 52 }))],
      ["secret prefix", digestWith(replaceSecret({ prefix: "sk-" }))],
      ["secret fingerprint", digestWith(replaceSecret({ fingerprint: "AbC123dEf457" }))],
      ["secret box", digestWith(replaceSecret({ box: "box-digest-other" }))],
      ["secret name", digestWith(replaceSecret({ name: "token" }))],
      ["include flipped off", digestWith(ITEMS, DECISIONS.map((d) => (d.ref === "a001" ? { ...d, include: false } : d)))],
      ["include flipped on", digestWith(ITEMS, DECISIONS.map((d) => (d.ref === "a003" ? { ...d, include: true } : d)))],
      ["a row added", digestWith([...ITEMS, view("a004")])],
    ]
    for (const [what, digest] of changed) expect(await digest, what).not.toBe(base)
  })

  test("it does not change with sources, sameValueAs or what the page only shows", async () => {
    const base = await digestWith(ITEMS)
    expect(await digestWith(replace("a001", { sources: [] }))).toBe(base)
    expect(await digestWith(replace("a001", { sameValueAs: ["a003"] }))).toBe(base)
    expect(await digestWith(replace("a001", { providerName: "Other", problem: "x", homesAllowed: [], home: { kind: "workspace" }, repo: null }))).toBe(base)
    expect(await digestWith(replace("a001", { binding: { value: ITEMS[0]!.binding.value, verified: false } }))).toBe(base)
  })

  test("unticking a row changes the digest, and an excluded row contributes only its ref", async () => {
    const input = adoptionDigestInput(ADP, ITEMS, DECISIONS)
    expect(input.items.find((item) => item.ref === "a003")).toEqual({ ref: "a003", include: false })
    // A row with no decision counts as excluded.
    expect(adoptionDigestInput(ADP, ITEMS, DECISIONS.slice(0, 2)).items.find((item) => item.ref === "a003")).toEqual({ ref: "a003", include: false })
    // Whatever an excluded row holds, its contribution is the same.
    const changedExcluded = replace("a003", { slug: "other", secrets: [], tags: ["z"], publicFields: { a: "b" } })
    expect(await digestWith(changedExcluded)).toBe(await digestWith(ITEMS))
    expect(adoptionDigestInput(ADP, ITEMS, DECISIONS).items.find((item) => item.ref === "a001")).toEqual({
      ref: "a001",
      include: true,
      slug: "item-a001",
      kind: "api-key",
      provider: "openai",
      binding: { hosts: ["api.openai.com"] },
      injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
      home: { kind: "project", project: "prj_billing" },
      tags: ["a", "b"],
      publicFields: {},
      secrets: [{ name: "key", length: 51, prefix: "sk-proj-", fingerprint: "AbC123dEf456", box: "box-digest-1" }],
    })
  })
})

const STORED: AdoptionCompareView = {
  holder: { type: "stored", id: "itm_openai", slug: "item-a001", kind: "api-key", version: 3, secrets: [{ name: "key", length: 51, prefix: "sk-proj-" }], rotatedAt: "2026-10-01T09:00:00.000Z", lastUsedAt: null },
  fields: [{ name: "key", result: "differs", fingerprint: "UnderHolderId1" }],
}
const COMPARED = replace("a001", { compare: STORED })

function decide(change: Partial<AdoptionDecisionInput>, ref = "a001"): AdoptionDecisionInput[] {
  return DECISIONS.map((d) => (d.ref === ref ? { ...d, ...change } : d))
}

describe("digest binds a conflict's decision", () => {
  const rename = (slug: string, repoint?: AdoptionDecisionInput["repoint"]) => decide({ action: "rename", slug, ...(repoint ? { repoint } : {}) })
  const point = (variable: string, env = "dev") => ({ project: "prj_billing", env, variable })

  test("it changes with the action, the target and its version, the slug and the repoints", async () => {
    const map = await digestWith(COMPARED, decide({ action: "map" }))
    const changed: [string, Promise<string>][] = [
      ["store", digestWith(COMPARED)],
      ["replace", digestWith(COMPARED, decide({ action: "replace" }))],
      ["rename", digestWith(COMPARED, rename("item-a001-linuxbox"))],
      ["target id", digestWith(replace("a001", { compare: { ...STORED, holder: { ...STORED.holder, id: "itm_other" } } }), decide({ action: "map" }))],
      ["target version", digestWith(replace("a001", { compare: { ...STORED, holder: { ...STORED.holder, version: 4 } as AdoptionCompareView["holder"] } }), decide({ action: "map" }))],
    ]
    for (const [what, digest] of changed) expect(await digest, what).not.toBe(map)
    const renamed = await digestWith(COMPARED, rename("item-a001-linuxbox"))
    expect(await digestWith(COMPARED, rename("item-a001-dev"))).not.toBe(renamed)
    expect(await digestWith(COMPARED, rename("item-a001-linuxbox", [point("OPENAI_API_KEY")]))).not.toBe(renamed)
    expect(await digestWith(COMPARED, rename("item-a001-linuxbox", [point("OPENAI_API_KEY")]))).not.toBe(await digestWith(COMPARED, rename("item-a001-linuxbox", [point("OPENAI_API_KEY", "staging")])))
    expect(await digestWith(COMPARED, rename("item-a001-linuxbox", []))).toBe(renamed)
  })

  test("it does not depend on the order of the repoints", async () => {
    const both = [point("OPENAI_API_KEY"), point("OPENAI_KEY", "staging")]
    expect(await digestWith(COMPARED, rename("item-a001-linuxbox", both))).toBe(await digestWith(COMPARED, rename("item-a001-linuxbox", [...both].reverse())))
  })

  test("a rename binds the new name, and a replace binds the fingerprints the target would carry", () => {
    const renamed = adoptionDigestInput(ADP, COMPARED, rename("item-a001-linuxbox", [point("OPENAI_KEY", "staging"), point("OPENAI_API_KEY")])).items.find((i) => i.ref === "a001")
    expect(renamed).toMatchObject({ slug: "item-a001-linuxbox", action: "rename", target: { id: "itm_openai", version: 3 }, repoint: [point("OPENAI_API_KEY"), point("OPENAI_KEY", "staging")] })
    const replaced = adoptionDigestInput(ADP, COMPARED, decide({ action: "replace" })).items.find((i) => i.ref === "a001")
    expect(replaced).toMatchObject({ slug: "item-a001", action: "replace", target: { id: "itm_openai", version: 3 }, secrets: [{ name: "key", length: 51, prefix: "sk-proj-", fingerprint: "UnderHolderId1", box: "box-digest-1" }] })
    expect(replaced).not.toHaveProperty("repoint")
    // Without a fingerprint under the target, a replace signs none, so the vault cannot store one.
    const unknown = replace("a001", { compare: { ...STORED, fields: [{ name: "key", result: "unknown", fingerprint: null }] } })
    expect(adoptionDigestInput(ADP, unknown, decide({ action: "replace" })).items.find((i) => i.ref === "a001")).toMatchObject({ secrets: [{ name: "key", fingerprint: null }] })
  })

  test("a staged holder is bound by its batch and ref, with no version", () => {
    const staged = replace("a001", { compare: { holder: { type: "staged", id: "adp_other/a7kq001", slug: "item-a001", kind: "api-key", version: null, secrets: [{ name: "key", length: 51, prefix: "sk-proj-" }], sources: [{ machine: "linuxbox", path: "/home/sam/code/billing-api/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [], mtime: "2026-10-30T12:00:00.000Z" }] }, fields: [{ name: "key", result: "same", fingerprint: null }] } })
    expect(adoptionDigestInput(ADP, staged, decide({ action: "map" })).items.find((i) => i.ref === "a001")).toMatchObject({ action: "map", target: { id: "adp_other/a7kq001", version: null } })
  })

  test("the compare result and the holder's hints are not signed", async () => {
    const base = await digestWith(COMPARED, decide({ action: "map" }))
    const hints = replace("a001", { compare: { holder: { ...STORED.holder, slug: "x", kind: "bearer-token", secrets: [], rotatedAt: null, lastUsedAt: "2026-11-01T00:00:00.000Z" } as AdoptionCompareView["holder"], fields: [{ name: "key", result: "same", fingerprint: "UnderHolderId1" }] } })
    expect(await digestWith(hints, decide({ action: "map" }))).toBe(base)
  })

  test("the repoints the action carries count every variable an included rename points, and nothing else", () => {
    const both = [point("OPENAI_API_KEY"), point("OPENAI_KEY", "staging")]
    expect(adoptionRepoints(decide({ action: "map" }))).toBe(0)
    expect(adoptionRepoints(rename("item-a001-linuxbox"))).toBe(0)
    expect(adoptionRepoints(rename("item-a001-linuxbox", both))).toBe(2)
    expect(adoptionRepoints([...rename("item-a001-linuxbox", both), { ref: "a009", include: true, home: { kind: "workspace" }, action: "rename", slug: "item-a009-dev", repoint: [point("OTHER_KEY")] }])).toBe(3)
    expect(adoptionRepoints(decide({ include: false, action: "rename", slug: "item-a001-linuxbox", repoint: both }))).toBe(0)
  })

  test("an excluded row binds only its ref, whatever it was decided", async () => {
    for (const change of [{ action: "replace" as const }, { action: "rename" as const, slug: "item-a001-linuxbox", repoint: [point("OPENAI_API_KEY")] }]) {
      const decisions = decide({ include: false, ...change })
      expect(adoptionDigestInput(ADP, COMPARED, decisions).items.find((i) => i.ref === "a001")).toEqual({ ref: "a001", include: false })
      expect(await digestWith(COMPARED, decisions)).toBe(await digestWith(COMPARED, decide({ include: false })))
    }
  })
})

describe("device status", () => {
  const approved = {
    adoption: ADP,
    status: "approved" as const,
    expiresAt: "2026-11-05T10:00:00.000Z",
    machines: [{ device: "dev_office", name: "sam-mac-mini", items: 3 }],
    created: [{ ref: "a001", slug: "openai-billing-api" }, { ref: "a002", slug: "openai-billing-api-linuxbox" }],
    mapped: [{ ref: "a003", slug: "stripe-billing-api" }],
    replaced: [{ ref: "a004", slug: "sentry-billing-api" }],
    refused: [{ ref: "a005", reason: "Left out at review." }],
  }
  const open = { adoption: ADP, status: "open" as const, expiresAt: "2026-11-05T10:00:00.000Z", machines: [], staged: [{ ref: "a001", slug: "openai-billing-api", machine: "sam-mac-mini" }] }

  test("after approval a machine learns only mapped, replaced or created, and while open only what is staged", () => {
    expect(AdoptionStatusSchema.parse(approved)).toEqual(approved)
    expect(AdoptionStatusSchema.parse(open)).toEqual(open)
    // A vault older than the outcomes sends created alone.
    const { mapped: _m, replaced: _r, ...older } = approved
    expect(AdoptionStatusSchema.parse(older)).toEqual(older)
  })

  test("it refuses a per-field result or a holder anywhere, before or after approval", () => {
    const leaks: unknown[] = [
      { ...open, staged: [{ ...open.staged[0], match: "same" }] },
      { ...open, staged: [{ ...open.staged[0], fields: [{ name: "key", result: "differs" }] }] },
      { ...open, staged: [{ ...open.staged[0], compare: { holder: { type: "stored", id: "itm_x" } } }] },
      { ...open, compare: [{ ref: "a001", result: "same" }] },
      { ...approved, mapped: [{ ref: "a003", slug: "stripe-billing-api", result: "same" }] },
      { ...approved, mapped: [{ ref: "a003", slug: "stripe-billing-api", same: true }] },
      { ...approved, replaced: [{ ref: "a004", slug: "sentry-billing-api", fields: [{ name: "key", result: "differs" }] }] },
      { ...approved, created: [{ ref: "a001", slug: "openai-billing-api", holder: "itm_x" }] },
      { ...approved, results: { a003: "same" } },
    ]
    for (const leak of leaks) expect(AdoptionStatusSchema.safeParse(leak).success, JSON.stringify(leak).slice(0, 160)).toBe(false)
  })
})

describe("index and keep-open", () => {
  function indexItem(overrides: Partial<AdoptionIndexInput["items"][number]> = {}): AdoptionIndexInput["items"][number] {
    return {
      ref: "a001",
      slug: "openai-billing-api",
      kind: "api-key",
      provider: "openai",
      home: "project",
      project: "prj_billing",
      include: true,
      exists: false,
      storeOnly: false,
      sources: [{ path: "/Users/sam/code/billing-api/.env", variable: "OPENAI_API_KEY", stale: [], mtime: "2026-10-30T12:00:00.000Z" }],
      uses: [{ project: "prj_billing", env: "dev", variable: "OPENAI_API_KEY", field: "key" }],
      ...overrides,
    }
  }

  test("an index lists every plan item, ticked or not, by name, kind, home, sources and uses", () => {
    const index = { machine: "sam-mac-mini", items: [indexItem(), indexItem({ ref: "a002", slug: "github-pat-gh", provider: "github-pat", home: "private", project: null, include: false, uses: [], sources: [{ path: "/Users/sam/.config/gh/hosts.yml", pointer: "/github.com/oauth_token", stale: ["file unchanged for 12 months"] }] })] }
    expect(AdoptionIndex.parse(index)).toEqual(index)
    expect(AdoptionIndex.safeParse({ machine: "m", items: Array.from({ length: ADOPTION_LIMITS.maxIndexItems }, () => indexItem()) }).success).toBe(true)
  })

  test("an index refuses a value, a length or a hash, and anything past its limits", () => {
    for (const bad of [
      { machine: "m", items: [{ ...indexItem(), value: "sk-proj-plaintext" }] },
      { machine: "m", items: [{ ...indexItem(), fingerprint: "AbC123" }] },
      { machine: "m", items: [indexItem({ sources: [{ path: "/a", stale: [], length: 51 } as never] })] },
      { machine: "m", items: [indexItem({ uses: [{ project: "prj_billing", env: "dev", variable: "OPENAI_API_KEY", field: "key", value: "x" } as never] })] },
      { machine: "m", items: [indexItem({ ref: "b001" })] },
      { machine: "m", items: [indexItem({ home: "member" as never })] },
      { machine: "m", items: [indexItem({ sources: [] })] },
      { machine: "m", items: Array.from({ length: ADOPTION_LIMITS.maxIndexItems + 1 }, () => indexItem()) },
      { machine: "", items: [] },
      { machine: "m", items: [], workspace: "acme" },
    ]) expect(AdoptionIndex.safeParse(bad).success, JSON.stringify(bad).slice(0, 120)).toBe(false)
  })

  test("keep-open names the expiry the page shows, and nothing else", () => {
    expect(AdoptionKeepOpen.parse({ expiresAt: "2026-11-05T10:00:00.000Z" })).toEqual({ expiresAt: "2026-11-05T10:00:00.000Z" })
    for (const bad of [{}, { expiresAt: "tomorrow" }, { expiresAt: "2026-11-05T10:00:00.000Z", days: 7 }]) expect(AdoptionKeepOpen.safeParse(bad).success, JSON.stringify(bad)).toBe(false)
  })
})
