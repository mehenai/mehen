import { describe, expect, test } from "bun:test"
import { catalogueCorpus, CATALOGUE_CORPUS_SCOPES, CATALOGUE_CORPUS_WINDOWS } from "../test/policy-catalogue-corpus.ts"
import { parseDestination, type Binding, type Destination, type Policy } from "./binding.ts"
import { sha256B64 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import {
  catalogueFloorKeys, catalogueFloorReason, cataloguePathMatches, isCataloguePath, POLICY_CATALOGUE_OUTLINES, POLICY_CATALOGUES, POLICY_FLOOR_REASONS, policyCatalogueFor, policyCatalogueNamed,
  type CatalogueEntry, type PolicyCatalogue, type PolicyFloorReason,
} from "./policy-catalogue.ts"
import { RULE_DEFAULT_DURATION } from "./policy-mode.ts"
import { ruleTermsFrom } from "./policy-rules.ts"
import {
  classifyPolicyRequest, evaluatePolicyFloor, GENERIC_POLICY_FLOOR_WORDS, POLICY_FLOOR, POLICY_SAFETY_PROFILES, policyCatalogueVerdict, policyPathFloorReasons, policyScopeEligibility, policyWideningEligibility,
  type PolicySafetyInput,
} from "./policy-safety.ts"
import { TEMPLATES } from "./templates.ts"

const ACCOUNT = "0123456789abcdef0123456789abcdef"
const encoded = (text: string): Uint8Array => new TextEncoder().encode(text)
const json = (value: unknown): Uint8Array => encoded(JSON.stringify(value))
function destination(method: string, url: string): Destination {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error("Invalid test destination")
  return parsed.destination
}
const request = (method: string, path: string, body: Uint8Array | null = null, contentType: string | null = body === null ? null : "application/json", contentEncoding: string | null = null): PolicySafetyInput => ({
  destination: destination(method, `https://api.example.test${path}`), body, contentType, contentEncoding,
})

const entry = (patch: Partial<CatalogueEntry> & Pick<CatalogueEntry, "id" | "path">): CatalogueEntry => ({ area: "things", effect: "routine", methods: ["POST"], body: "json", words: "Makes a thing", since: 1, additionalPermission: false, ...patch })
const FIXTURE: PolicyCatalogue = {
  template: "example",
  version: 2,
  hosts: ["api.example.test"],
  areas: [{ id: "things", name: "Things", words: "Makes and changes things" }, { id: "blobs", name: "Blobs", words: "Stores bytes" }],
  entries: [
    entry({ id: "example.thing-create", path: `/accounts/{account}/things` }),
    entry({ id: "example.thing-update", methods: ["PATCH"], path: `/accounts/{account}/things/{name}`, floorKeys: { env_vars: "credential", source: "persistence", ssh_keys: "credential", bindings: "persistence" } }),
    entry({ id: "example.thing-replace", methods: ["PUT"], path: `/accounts/{account}/things/{name}`, since: 2 }),
    entry({ id: "example.thing-move", effect: "destructive", methods: ["PUT"], path: `/accounts/{account}/things/{name}` }),
    entry({ id: "example.blob-put", area: "blobs", methods: ["PUT"], path: `/accounts/{account}/blobs/{id}`, body: "data" }),
    entry({ id: "example.blob-meta", area: "blobs", methods: ["PUT"], path: `/accounts/{account}/blobs/{id}/meta`, body: "data", floorKeys: { env_vars: "credential" } }),
    entry({ id: "example.blob-touch", area: "blobs", methods: ["POST"], path: `/accounts/{account}/blobs/{id}/touch`, body: "none" }),
    entry({ id: "example.comment", methods: ["POST"], path: "/repos/{owner}/{repo}/issues/{number}/comments", body: { reader: "github.comment" } }),
    entry({ id: "example.locked-thing", methods: ["POST"], path: `/accounts/{account}/things/{name}/lock` }),
  ],
  floor: [
    { id: "example.thing-lock", reason: "sharing", methods: ["POST", "PUT"], path: `/accounts/{account}/things/{name}/lock/**`, words: "Locks a thing for others", since: 1 },
    { id: "example.thing-key", reason: "credential", methods: ["GET"], path: `/accounts/{account}/things/{id}/key`, words: "Reads a thing's key", since: 1 },
  ],
}

describe("GitHub and Stripe, moved to catalogue v2", () => {
  // The corpus's answers, worked out a chunk at a time so that no one test
  // runs long under CI's load; each chunk is kept for the digest.
  const CORPUS = catalogueCorpus()
  const CHUNK = 500
  const chunks = new Map<number, unknown[]>()
  const answersOf = (chunk: number): unknown[] => {
    const known = chunks.get(chunk)
    if (known !== undefined) return known
    const answers = CORPUS.slice(chunk * CHUNK, (chunk + 1) * CHUNK).map(({ input }) => {
      const t = TEMPLATES[input.destination.host === "api.github.com" ? "github-pat" : "stripe"]!
      const anchor = { ...input, body: input.body ?? null, contentType: input.contentType ?? null, contentEncoding: input.contentEncoding ?? null, item: "x-key", itemId: "itm_x0000001", asker: { device: "dev_x", workload: null }, policy: t.policy as Policy, binding: t.binding as Binding, secretPrefixes: [] }
      const made = ruleTermsFrom(anchor, { path: input.destination.path, ttlSeconds: RULE_DEFAULT_DURATION })
      const windows = CATALOGUE_CORPUS_WINDOWS.filter((s) => s.host === input.destination.host).map((s) => policyWideningEligibility(input, s, { hosts: [s.host] }).reason)
      return [classifyPolicyRequest(input), evaluatePolicyFloor(input), made.ok ? "ok" : made.reason, windows]
    })
    chunks.set(chunk, answers)
    return answers
  }
  const CHUNKS = Array.from({ length: Math.ceil(CORPUS.length / CHUNK) }, (_, i) => i)

  test.each(CHUNKS)("answer requests in chunk %d of the corpus", (chunk) => {
    expect(answersOf(chunk).length).toBe(Math.min(CHUNK, CORPUS.length - chunk * CHUNK))
  })

  test("give every request the answers mehen-policy-safety/v4 gave", async () => {
    const answers = CHUNKS.flatMap((chunk) => answersOf(chunk))
    const scopes = CATALOGUE_CORPUS_SCOPES.map((s) => policyScopeEligibility(s, { hosts: [s.host] }))
    expect(answers).toHaveLength(6048)
    // The digest of the same answers computed at ad1313f7, before the move.
    expect(await sha256B64(canonicalJson({ answers, scopes }))).toBe("HPfH27MaBx8mXuLruMj1fs6iRDApC-d658URBl7sW0Y")
  })

  test("are the areas issues and products, and the old widening windows read the same entries", () => {
    expect(policyCatalogueFor("api.github.com")).toMatchObject({ template: "github", version: 1, areas: [{ id: "issues" }] })
    expect(policyCatalogueFor("api.stripe.com")).toMatchObject({ template: "stripe", version: 1, areas: [{ id: "products" }] })
    expect(policyCatalogueFor("api.cloudflare.com")).toMatchObject({ template: "cloudflare-api-token", version: 2 })
    expect(policyCatalogueNamed("github")?.entries.map((e) => [e.id, e.area, e.effect])).toEqual([
      ["github.issue-create", "issues", "routine"], ["github.issue-update", "issues", "routine"], ["github.comment-create", "issues", "routine"], ["github.comment-update", "issues", "routine"], ["github.comment-delete", "issues", "destructive"],
    ])
    expect(policyCatalogueNamed("stripe")?.entries.map((e) => [e.id, e.area])).toEqual([["stripe.products-create", "products"], ["stripe.products-update", "products"], ["stripe.prices-create", "products"], ["stripe.prices-update", "products"]])
    for (const id of ["github-pat", "github-oauth"]) expect(POLICY_SAFETY_PROFILES.find((p) => p.id === id)?.widenable).toEqual(policyCatalogueNamed("github")?.entries)
    expect(POLICY_SAFETY_PROFILES.find((p) => p.id === "stripe")?.widenable).toEqual(policyCatalogueNamed("stripe")?.entries)
  })
})

// The literal segments of a catalogue path, which a request to it must
// spell exactly: what the floor words would read in it.
const literalPath = (path: string): string => `/${path.slice(1).split("/").filter((s) => s !== "*" && s !== "**" && !s.startsWith("{")).join("/")}`
function unreviewedFloorWords(e: CatalogueEntry): string[] {
  if (e.floorWordsReviewed !== undefined && e.floorWordsReviewed.trim() !== "") return []
  const path = literalPath(e.path)
  const loose = path.toLowerCase().replace(/[^a-z0-9]/g, "")
  return [...policyPathFloorReasons(path), ...GENERIC_POLICY_FLOOR_WORDS.filter((w) => loose.includes(w)).map((w) => `generic.${w}`)]
}

describe("every catalogue", () => {
  const ids = POLICY_CATALOGUES.flatMap((c) => [...c.entries.map((e) => e.id), ...c.floor.map((f) => f.id)])

  test("has a growing version, its own hosts and template, and unique ids", () => {
    for (const c of POLICY_CATALOGUES) {
      expect(Number.isSafeInteger(c.version) && c.version >= 1, c.template).toBe(true)
      expect(c.areas.map((a) => a.id), c.template).toEqual([...new Set(c.areas.map((a) => a.id))])
      expect(c.areas.every((a) => /^[a-z][a-z0-9-]{0,31}$/.test(a.id) && a.name !== "" && a.words !== ""), c.template).toBe(true)
    }
    const hosts = POLICY_CATALOGUES.flatMap((c) => c.hosts)
    expect(hosts).toEqual([...new Set(hosts)])
    expect(POLICY_CATALOGUES.map((c) => c.template)).toEqual([...new Set(POLICY_CATALOGUES.map((c) => c.template))])
    expect(ids).toEqual([...new Set(ids)])
    expect(ids.some((id) => id.includes(":") || POLICY_FLOOR.some((f) => f.id === id))).toBe(false)
  })

  test("names for each entry and floor an area it has, words, a typed path, and the version it arrived in", () => {
    for (const c of [...POLICY_CATALOGUES, ...POLICY_CATALOGUE_OUTLINES, FIXTURE]) {
      for (const e of c.entries) {
        expect(c.areas.some((a) => a.id === e.area), e.id).toBe(true)
        expect(e.words !== "" && e.methods.length > 0 && isCataloguePath(e.path) && !e.path.includes("**"), e.id).toBe(true)
        expect(Number.isSafeInteger(e.since) && e.since >= 1 && e.since <= c.version, e.id).toBe(true)
        for (const reason of Object.values(e.floorKeys ?? {})) expect(POLICY_FLOOR_REASONS, e.id).toContain(reason)
      }
      for (const f of c.floor) {
        expect(f.words !== "" && f.methods.length > 0 && isCataloguePath(f.path, true), f.id).toBe(true)
        expect(Number.isSafeInteger(f.since) && f.since >= 1 && f.since <= c.version, f.id).toBe(true)
      }
    }
  })

  test("names a floor word in an entry's path only where floorWordsReviewed says why", () => {
    for (const c of POLICY_CATALOGUES) for (const e of c.entries) expect(unreviewedFloorWords(e), e.id).toEqual([])
  })

  test("the floor-words guard catches an unreviewed floor word, and not one in a typed segment's name", () => {
    expect(unreviewedFloorWords(entry({ id: "x.messages", path: "/accounts/{account}/queues/{id}/messages" }))).toEqual(["send"])
    expect(unreviewedFloorWords(entry({ id: "x.secret", path: "/accounts/{account}/workers/scripts/{name}/secrets" }))).toEqual(["credential", "generic.secret"])
    expect(unreviewedFloorWords(entry({ id: "x.webhook", path: "/v1/web-hooks" }))).toEqual(["persistence", "generic.hook", "generic.webhook"])
    expect(unreviewedFloorWords(entry({ id: "x.reviewed", path: "/accounts/{account}/queues/{id}/messages", floorWordsReviewed: "The account's own queue" }))).toEqual([])
    expect(unreviewedFloorWords(entry({ id: "x.typed", path: "/accounts/{account}/things/{name}" }))).toEqual([])
  })
})

describe("typed path segments", () => {
  test.each([
    ["/accounts/{account}/things", `/accounts/${ACCOUNT}/things`, true],
    ["/accounts/{account}/things", "/accounts/0123456789ABCDEF0123456789ABCDEF/things", false],
    ["/accounts/{account}/things", "/accounts/0123/things", false],
    ["/zones/{zone}/dns_records", `/zones/${ACCOUNT}/dns_records`, true],
    ["/things/{id}", `/things/${ACCOUNT}`, true],
    ["/things/{id}", "/things/0e4f3a1c-6b2d-4c8e-9a7f-1d2c3b4a5e6f", true],
    ["/things/{id}", "/things/0e4f3a1c6b2d4c8e9a7f1d2c3b4a5e6", false],
    ["/things/{id}", "/things/my-thing", false],
    ["/things/{name}", "/things/my-thing.v2_1", true],
    ["/things/{name}", "/things/-leading", false],
    ["/things/{name}", `/things/${"a".repeat(128)}`, true],
    ["/things/{name}", `/things/${"a".repeat(129)}`, false],
    ["/things/{name}", "/things/a:b", false],
    ["/repos/{owner}/{repo}/issues/{number}", "/repos/alex/.github/issues/12", true],
    ["/repos/{owner}/{repo}/issues/{number}", "/repos/a.b/vault/issues/12", false],
    ["/repos/{owner}/{repo}/issues/{number}", "/repos/alex/vault/issues/012", false],
    ["/v1/products/*", "/v1/products/a:b", true],
    ["/v1/products/*", "/v1/products", false],
    ["/things/{name}", "/things/a/b", false],
    ["/things/{name}", "/things/a/", false],
    ["/things/**", "/things", true],
    ["/things/**", "/things/a/b/", true],
    ["/things/lock", "/things/LOCK", false],
  ] as const)("%s against %s", (pattern, path, matched) => expect(cataloguePathMatches(pattern, path)).toBe(matched))

  test("a floor's literal segments match in any case, and its typed segments any one segment", () => {
    expect(cataloguePathMatches("/things/lock/**", "/Things/LOCK/x", true)).toBe(true)
    for (const account of [ACCOUNT.toUpperCase(), "not-hex", "a:b"]) expect(cataloguePathMatches("/accounts/{account}/lock", `/accounts/${account}/lock`, true), account).toBe(true)
    expect(cataloguePathMatches("/accounts/{account}/lock", "/accounts//lock", true)).toBe(false)
    expect(cataloguePathMatches("/accounts/{account}/lock", `/accounts/${ACCOUNT}/x/lock`, true)).toBe(false)
  })

  test("a catalogue path is literal, * or typed segments, and ** only last in a floor", () => {
    expect(isCataloguePath("/accounts/{account}/things/{name}")).toBe(true)
    expect(isCataloguePath("/accounts/{account}/things/**")).toBe(false)
    expect(isCataloguePath("/accounts/{account}/things/**", true)).toBe(true)
    for (const path of ["/accounts/{acct}/things", "accounts", "/a/**/b", "/a/{name", "/a/b c"]) expect(isCataloguePath(path, true), path).toBe(false)
  })
})

describe("reading a request against a catalogue", () => {
  const verdict = (input: PolicySafetyInput) => policyCatalogueVerdict(input, FIXTURE)

  test("an entry matches its method and typed path, with no query string", () => {
    expect(verdict(request("POST", `/accounts/${ACCOUNT}/things`, json({ name: "a" }))).entry?.id).toBe("example.thing-create")
    expect(verdict(request("POST", `/accounts/${ACCOUNT}/things?x=1`, json({ name: "a" }))).entry).toBeNull()
    expect(verdict(request("PATCH", `/accounts/${ACCOUNT}/things`, json({ name: "a" }))).entry).toBeNull()
    expect(verdict(request("POST", "/accounts/not-hex/things", json({ name: "a" }))).entry).toBeNull()
    expect(policyCatalogueVerdict(request("POST", `/accounts/${ACCOUNT}/things`, json({ name: "a" })), policyCatalogueFor("api.github.com"))).toEqual({ floor: [], entry: null })
  })

  test("a json entry takes one strict JSON object or none, as the safety checks read it", () => {
    expect(verdict(request("POST", `/accounts/${ACCOUNT}/things`)).entry?.id).toBe("example.thing-create")
    for (const [body, type] of [[json([{ name: "a" }]), "application/json"], [encoded("name=a"), "application/x-www-form-urlencoded"], [json({ name: "a" }), "multipart/form-data; boundary=a"], [json({ jsonrpc: "2.0", method: "x" }), "application/json"]] as const) {
      expect(verdict(request("POST", `/accounts/${ACCOUNT}/things`, body, type)).entry, type).toBeNull()
    }
  })

  test("a data entry takes stored bytes, refusing only a method override, an unread charset or a coding", () => {
    const blob = `/accounts/${ACCOUNT}/blobs/${ACCOUNT}`
    expect(verdict(request("PUT", blob, encoded("any bytes at all"), "application/octet-stream")).entry?.id).toBe("example.blob-put")
    expect(verdict(request("PUT", blob, encoded("--a\r\nopaque\r\n--a--"), "multipart/form-data; boundary=a")).entry?.id).toBe("example.blob-put")
    expect(verdict(request("PUT", blob, encoded("note=x&_method=DELETE"), "application/x-www-form-urlencoded")).entry).toBeNull()
    expect(verdict(request("PUT", blob, encoded('{"note":"x"}'), "application/json; charset=utf-7")).entry).toBeNull()
    expect(verdict(request("PUT", blob, encoded("bytes"), "application/octet-stream", "gzip")).entry).toBeNull()
  })

  test("a json or reader entry refuses a body whose type declares an unread charset, as a data entry does", () => {
    for (const [path, body] of [[`/accounts/${ACCOUNT}/things`, json({ name: "a" })], ["/repos/alex/vault/issues/12/comments", json({ body: "Hi" })]] as const) {
      expect(verdict(request("POST", path, body, "application/json; charset=utf-8")).entry, path).not.toBeNull()
      for (const charset of ["utf-7", '"UTF-7"', "utf-32", "ucs-2", ""]) expect(verdict(request("POST", path, body, `application/json; charset=${charset}`)).entry, `${path} ${charset}`).toBeNull()
    }
  })

  test("a none entry takes no body", () => {
    const touch = `/accounts/${ACCOUNT}/blobs/${ACCOUNT}/touch`
    expect(verdict(request("POST", touch)).entry?.id).toBe("example.blob-touch")
    expect(verdict(request("POST", touch, json({}))).entry).toBeNull()
    expect(verdict(request("POST", touch, null, "multipart/form-data; boundary=a")).entry).toBeNull()
  })

  test("a reader decides whether the body is its entry's", () => {
    const comments = "/repos/alex/vault/issues/12/comments"
    expect(verdict(request("POST", comments, json({ body: "Hi" }))).entry?.id).toBe("example.comment")
    expect(verdict(request("POST", comments, json({ body: "Hi", owner: "foreign" }))).entry).toBeNull()
    expect(verdict(request("POST", comments, json({ body: "Hi" }), "multipart/form-data; boundary=a")).entry).toBeNull()
  })

  test("a destructive entry wins over a routine one on the same route", () => {
    expect(verdict(request("PUT", `/accounts/${ACCOUNT}/things/one`, json({ name: "a" }))).entry?.id).toBe("example.thing-move")
  })

  test("a catalogue floor wins over every entry, in any case, and is a mandatory floor reason", () => {
    const lock = request("POST", `/accounts/${ACCOUNT}/things/one/lock`, json({ name: "a" }))
    expect(verdict(lock)).toEqual({ floor: [{ id: "example.thing-lock", reason: "sharing" }], entry: null })
    expect(verdict(request("POST", `/accounts/${ACCOUNT}/things/one/LOCK/deeper?x=1`, json({ name: "a" }))).floor).toEqual([{ id: "example.thing-lock", reason: "sharing" }])
    expect(verdict(request("GET", `/accounts/${ACCOUNT}/things/one/lock`)).floor).toEqual([])
    expect(evaluatePolicyFloor(lock, FIXTURE)).toEqual({ action: "approve", reasons: ["example.thing-lock"] })
    for (const path of [`/accounts/${ACCOUNT.toUpperCase()}/things/one/lock`, "/accounts/Not-Hex/things/-one/lock"]) {
      expect(verdict(request("POST", path, json({ name: "a" }))).floor, path).toEqual([{ id: "example.thing-lock", reason: "sharing" }])
      expect(evaluatePolicyFloor(request("POST", path, json({ name: "a" })), FIXTURE).reasons, path).toContain("example.thing-lock")
    }
  })

  test("a catalogue floor holds every loose form of its path a template floor holds", () => {
    const keyed = `/accounts/${ACCOUNT}/things/${ACCOUNT}`
    for (const path of [`${keyed}/key`, `${keyed}/key/`, `${keyed}/KEY`, `${keyed}/key;x=1`, `${keyed}/key.json`, `${keyed}/%6Bey`, `/accounts/${ACCOUNT.toUpperCase()}/things/not-an-id/key`, `${keyed}/key?x=1`]) {
      const read = request("GET", path)
      expect(verdict(read).floor, path).toEqual([{ id: "example.thing-key", reason: "credential" }])
      expect(evaluatePolicyFloor(read, FIXTURE).reasons, path).toContain("example.thing-key")
    }
    for (const path of [`${keyed}/keys`, `${keyed}/key/more`, `${keyed}/a/key`]) expect(verdict(request("GET", path)).floor, path).toEqual([])
    expect(verdict(request("HEAD", `${keyed}/key`)).floor).toEqual([])
  })

  test("an entry's floor keys hold on every spelling of its route, not only the one it matches", () => {
    for (const path of [`/accounts/${ACCOUNT.toUpperCase()}/things/one`, `/accounts/${ACCOUNT}/things/-one`, `/accounts/${ACCOUNT}/things/one/`, `/accounts/${ACCOUNT}/THINGS/one`, `/accounts/${ACCOUNT}/things/one;x=1`]) {
      const patch = request("PATCH", path, json({ env_vars: {} }))
      expect(verdict(patch), path).toEqual({ floor: [{ id: "example.thing-update:credential", reason: "credential" }], entry: null })
      expect(evaluatePolicyFloor(patch, FIXTURE).reasons, path).toContain("example.thing-update:credential")
      expect(verdict(request("PATCH", path, json({ name: "renamed" }))), path).toEqual({ floor: [], entry: null })
    }
  })

  test("a floor key anywhere in a JSON body, in any case, makes the request floor", () => {
    const thing = `/accounts/${ACCOUNT}/things/one`
    expect(verdict(request("PATCH", thing, json({ name: "renamed" })))).toMatchObject({ floor: [], entry: { id: "example.thing-update" } })
    expect(verdict(request("PATCH", thing, json({ deployment_configs: { production: { ENV_VARS: { A: { value: "x" } } } } })))).toEqual({ floor: [{ id: "example.thing-update:credential", reason: "credential" }], entry: null })
    expect(verdict(request("PATCH", `${thing}?x=1`, json({ list: [{ Source: {} }] }))).floor).toEqual([{ id: "example.thing-update:persistence", reason: "persistence" }])
    expect(catalogueFloorKeys({ env_vars: "credential" }, encoded('{"note":"env_vars"}'))).toEqual({ reasons: [], readable: true })
    expect(catalogueFloorKeys({ env_vars: "credential" }, encoded("env_vars=x"))).toEqual({ reasons: [], readable: false })
    expect(evaluatePolicyFloor(request("PATCH", thing, json({ env_vars: {} })), FIXTURE)).toEqual({ action: "approve", reasons: ["example.thing-update:credential"] })
  })

  test("a floor key folds each character at least as broadly as Go's encoding/json", () => {
    const thing = `/accounts/${ACCOUNT}/things/one`
    for (const key of ["env_var\u017f", "ENV_VAR\u017F", "ssh_\u212aeys", "SSH_\u212AEYS"]) {
      expect(verdict(request("PATCH", thing, json({ deployment: { [key]: {} } }))), key).toEqual({ floor: [{ id: "example.thing-update:credential", reason: "credential" }], entry: null })
      expect(evaluatePolicyFloor(request("PATCH", thing, json({ [key]: {} })), FIXTURE), key).toEqual({ action: "approve", reasons: ["example.thing-update:credential"] })
    }
  })

  test("a floor key folds a capital I with dot above to I, as Go does", () => {
    const thing = `/accounts/${ACCOUNT}/things/one`
    for (const key of ["b\u0130ndings", "B\u0130ND\u0130NGS", "b\u0131ndings"]) {
      expect(verdict(request("PATCH", thing, json({ deployment: { [key]: [] } }))), key).toEqual({ floor: [{ id: "example.thing-update:persistence", reason: "persistence" }], entry: null })
      expect(catalogueFloorKeys({ bindings: "persistence" }, json({ [key]: [] })), key).toEqual({ reasons: ["persistence"], readable: true })
    }
  })

  test("a body nested 100000 deep is read for floor keys without throwing, and is floor", () => {
    const thing = `/accounts/${ACCOUNT}/things/one`
    const depth = 100000
    const deep = encoded(`${'{"a":['.repeat(depth)}{"env_vars":1}${"]}".repeat(depth)}`)
    expect(catalogueFloorKeys({ env_vars: "credential" }, deep)).toEqual({ reasons: ["credential"], readable: false })
    expect(verdict(request("PATCH", thing, deep))).toEqual({ floor: [{ id: "example.thing-update:credential", reason: "credential" }], entry: null })
    expect(evaluatePolicyFloor(request("PATCH", thing, deep), FIXTURE)).toMatchObject({ action: "approve", reasons: expect.arrayContaining(["example.thing-update:credential"]) })
    const nested = (n: number): Uint8Array => encoded(`${'{"a":'.repeat(n / 2)}${"[".repeat(n / 2)}${"]".repeat(n / 2)}${"}".repeat(n / 2)}`)
    expect(evaluatePolicyFloor(request("PATCH", thing, nested(depth)), FIXTURE).action).toBe("approve")
    expect(nested(16000).length).toBeLessThanOrEqual(64 * 1024)
    expect(() => evaluatePolicyFloor(request("PATCH", thing, nested(16000)), FIXTURE)).not.toThrow()
  })

  test("an entry with floor keys does not match a body it cannot read as strict JSON", () => {
    const unreadable: [string, Uint8Array][] = [
      ["duplicate key", encoded('{"name":"a","name":"b"}')],
      ["invalid UTF-8", new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])],
      ["not JSON", encoded("env_vars=x")],
      ["a byte order mark", encoded('\ufeff{"env_vars":1}')],
      ["empty", new Uint8Array()],
      ["over 64 KiB", json({ note: "x".repeat(65 * 1024) })],
    ]
    for (const [path, method, type] of [[`/accounts/${ACCOUNT}/things/one`, "PATCH", "application/json"], [`/accounts/${ACCOUNT}/blobs/${ACCOUNT}/meta`, "PUT", "application/octet-stream"]] as const) {
      expect(verdict(request(method, path, json({ name: "a" }), type)).entry, path).not.toBeNull()
      expect(verdict(request(method, path)).entry, path).not.toBeNull()
      for (const [name, body] of unreadable) {
        expect(verdict(request(method, path, body, type)).entry, `${path} ${name}`).toBeNull()
        expect(evaluatePolicyFloor(request(method, path, body, type), FIXTURE).action, `${path} ${name}`).toBe("approve")
      }
    }
    expect(catalogueFloorKeys({ env_vars: "credential" }, json({ env_vars: 1, note: "x".repeat(65 * 1024) }))).toEqual({ reasons: ["credential"], readable: false })
    expect(catalogueFloorKeys(undefined, encoded("env_vars=x"))).toEqual({ reasons: [], readable: true })
  })

  test("a request that is an entry skips the body check and the generic words; one that is not keeps both", () => {
    const blob = request("PUT", `/accounts/${ACCOUNT}/blobs/${ACCOUNT}`, encoded("token=abc"), "application/octet-stream")
    expect(evaluatePolicyFloor(blob, FIXTURE)).toEqual({ action: "allow", reasons: [] })
    expect(evaluatePolicyFloor(blob, null)).toEqual({ action: "approve", reasons: ["safety.body-opaque"] })
    const keyed = request("POST", `/accounts/${ACCOUNT}/things?key=1`, json({ name: "a" }))
    expect(evaluatePolicyFloor(keyed, FIXTURE).reasons).toEqual(["generic.key"])
  })

  test("a reason id reads back as the floor reason it gives", () => {
    expect(catalogueFloorReason("github.issue-create:credential")).toBe("credential")
    expect(catalogueFloorReason("github.issue-create:nonsense")).toBeNull()
    expect(catalogueFloorReason("github.issue-create")).toBeNull()
    expect(catalogueFloorReason("example.thing-lock")).toBeNull()
  })
})

const BOUNDARY = "----formdata-undici-012345678901"
const UPLOAD_TYPE = `multipart/form-data; boundary=${BOUNDARY}`
type Part = { name: string; filename?: string; type?: string; body: string }
const part = (name: string, body: string, type?: string, filename?: string): Part => ({ name, body, ...(type === undefined ? {} : { type }), ...(filename === undefined ? {} : { filename }) })
const multipart = (...parts: Part[]): Uint8Array => encoded(`${parts.map((p) => `--${BOUNDARY}\r\nContent-Disposition: form-data; name="${p.name}"${p.filename === undefined ? "" : `; filename="${p.filename}"`}\r\n${p.type === undefined ? "" : `Content-Type: ${p.type}\r\n`}\r\n${p.body}\r\n`).join("")}--${BOUNDARY}--\r\n`)
const metadataPart = (value: unknown): Part => part("metadata", JSON.stringify(value), "application/json")
const workerModule = part("index.js", "export default { fetch() { return new Response('ok') } }", "application/javascript+module", "index.js")

const READERS: PolicyCatalogue = {
  template: "example-readers",
  version: 1,
  hosts: ["api.example.test"],
  areas: [{ id: "things", name: "Things", words: "Makes and changes things" }],
  entries: [
    entry({ id: "example.record", path: "/zones/{zone}/records", body: { reader: "cloudflare.dns-record" } }),
    entry({ id: "example.worker", methods: ["PUT"], path: "/accounts/{account}/scripts/{name}", body: { reader: "cloudflare.worker-upload" } }),
  ],
  floor: [],
}

describe("the Cloudflare body readers", () => {
  const read = (input: PolicySafetyInput) => policyCatalogueVerdict(input, READERS)
  const record = (body: Uint8Array | null, contentType: string | null = "application/json") => request("POST", `/zones/${ACCOUNT}/records`, body, contentType)
  const worker = (body: Uint8Array, contentType = UPLOAD_TYPE, contentEncoding: string | null = null) => request("PUT", `/accounts/${ACCOUNT}/scripts/my-worker`, body, contentType, contentEncoding)
  const routine = { floor: [], entry: expect.objectContaining({ id: expect.any(String) }) }
  const notCovered = { floor: [], entry: null }
  const floorOf = (id: string, reason: PolicyFloorReason) => ({ floor: [{ id: `${id}:${reason}`, reason }], entry: null })

  test("dns-record: an A, AAAA or CNAME record whose name has no label starting with _ is the entry", () => {
    for (const value of [{ type: "A", name: "www", content: "192.0.2.1" }, { type: "AAAA", name: "example.com", content: "2001:db8::1" }, { type: "CNAME", name: "app.example.com", content: "x.pages.dev", proxied: true }, { type: "cname", name: "blog", content: "x" }]) {
      expect(read(record(json(value))), JSON.stringify(value)).toEqual(routine)
    }
  })

  test("dns-record: any other type, a label starting with _, or a type or name it cannot read is persistence", () => {
    const bodies: unknown[] = [
      ...["MX", "TXT", "NS", "CAA", "SRV", "DS", "HTTPS", "SVCB", "PTR", "A ", "\u0391"].map((type) => ({ type, name: "www", content: "x" })),
      ...["_dmarc", "_acme-challenge.www", "www._domainkey.example.com", "\uff3fdmarc", " _x", "a\u3002_b", "a\uff0e_b"].map((name) => ({ type: "CNAME", name, content: "x" })),
      { name: "www", content: "192.0.2.1" }, { type: "A", content: "192.0.2.1" }, { type: ["A"], name: "www" }, { type: "A", name: 1 },
      { type: "A", TYPE: "TXT", name: "www" }, { type: "A", name: "www", Name: "_dmarc" }, [{ type: "A", name: "www" }],
    ]
    for (const body of bodies) {
      expect(read(record(json(body))), JSON.stringify(body)).toEqual(floorOf("example.record", "persistence"))
      expect(evaluatePolicyFloor(record(json(body)), READERS).reasons, JSON.stringify(body)).toContain("example.record:persistence")
    }
    for (const [body, type] of [[encoded("type=A&name=www"), "application/x-www-form-urlencoded"], [encoded('{"type":"A","type":"A","name":"www"}'), "application/json"], [null, null], [encoded("not json"), "application/json"]] as const) {
      expect(read(record(body, type)), String(type)).toEqual(floorOf("example.record", "persistence"))
    }
  })

  test("dns-record: a name is routine only in letters, digits, *, @, . and -, so punycode and a wildcard pass", () => {
    for (const name of ["xn--bcher-kva", "*.dev", "@", "api.example.com", "A-1.b"]) expect(read(record(json({ type: "A", name, content: "192.0.2.1" }))), name).toEqual(routine)
  })

  test.each(["\u00ad_acme-challenge", "\u200b_dmarc", "\\095dmarc", "a_b", "b\u00fccher", "www ", "", "a\u2060b", "a/b"])("dns-record: the name %j is persistence", (name) => {
    expect(read(record(json({ type: "CNAME", name, content: "x.example.net" })))).toEqual(floorOf("example.record", "persistence"))
  })

  test("worker-upload: metadata and typed modules are the entry, and no body check holds them", () => {
    const body = multipart(metadataPart({ main_module: "index.js", compatibility_date: "2026-11-01", bindings: [{ type: "ai", name: "AI" }, { type: "plain_text", name: "MODE", text: "prod" }], keep_bindings: [], observability: { logs: { enabled: true, destinations: ["cloudflare"] } } }), workerModule,
      part("lib.wasm", "\u0000asm", "application/wasm", "lib.wasm"), part("index.js.map", "{}", "application/source-map", "index.js.map"), part("data.txt", "x", "text/plain", "data.txt"), part("blob.bin", "x", "application/octet-stream", "blob.bin"))
    expect(read(worker(body))).toEqual(routine)
    expect(evaluatePolicyFloor(worker(body), READERS)).toEqual({ action: "allow", reasons: [] })
    expect(evaluatePolicyFloor(worker(body), null).reasons).toEqual(["safety.batch"])
  })

  test("worker-upload: a secret binding is credential, an email binding send, logs sent elsewhere persistence, and a class deleted or moved destructive", () => {
    const cases: [unknown, PolicyFloorReason][] = [
      ...["secret_text", "secret_key", "secrets_store_secret", "SECRET_TEXT", "Secret_Key"].map((type): [unknown, PolicyFloorReason] => [{ bindings: [{ type, name: "API_KEY" }] }, "credential"]),
      [{ BINDINGS: [{ Type: "secret_text", name: "API_KEY" }] }, "credential"],
      [{ bindings: [{ type: "send_email", name: "MAIL" }] }, "send"],
      [{ logpush: true }, "persistence"], [{ LogPush: false }, "persistence"], [{ tail_consumers: [{ service: "tail" }] }, "persistence"], [{ streaming_tail_consumers: [] }, "persistence"],
      [{ observability: { logs: { destinations: ["my-collector"] } } }, "persistence"], [{ observability: { traces: { destinations: "cloudflare" } } }, "persistence"],
      [{ migrations: { deleted_classes: ["Counter"] } }, "destructive"], [{ migrations: { steps: [{ transferred_classes: [{ from: "A", from_script: "x", to: "B" }] }] } }, "destructive"],
      [{ exports: { Counter: { type: "durable-object", state: "deleted" } } }, "destructive"], [{ exports: { Counter: { type: "durable-object", state: "transferred", transferred_to: "other" } } }, "destructive"],
      [{ exports: { Counter: { type: "durable-object", state: "expecting-transfer", transfer_from: "other", storage: "sqlite" } } }, "destructive"],
      [{ bindings: [{ type: "secret_text", name: "A" }], logpush: true }, "credential"],
    ]
    for (const [metadata, reason] of cases) {
      expect(read(worker(multipart(metadataPart({ main_module: "index.js", ...metadata as object }), workerModule))), JSON.stringify(metadata)).toEqual(floorOf("example.worker", reason))
    }
    const unread = multipart(metadataPart({ main_module: "index.js", bindings: [{ type: "secret_text", name: "A" }] }), part("run.sh", "x", "application/x-sh"))
    expect(read(worker(unread))).toEqual(floorOf("example.worker", "credential"))
    expect(evaluatePolicyFloor(worker(unread), READERS).reasons).toContain("example.worker:credential")
  })

  const uploadWith = (metadata: object) => read(worker(multipart(metadataPart({ main_module: "index.js", ...metadata }), workerModule)))

  test("worker-upload: keep_bindings naming secret types is credential", () => {
    expect(uploadWith({ keep_bindings: ["secret_text", "secret_key"] })).toEqual(floorOf("example.worker", "credential"))
  })

  test("worker-upload: keep_bindings naming only plain_text is credential, since any kept binding is one the body cannot show", () => {
    expect(uploadWith({ keep_bindings: ["plain_text"] })).toEqual(floorOf("example.worker", "credential"))
    expect(uploadWith({ Keep_Bindings: "plain_text" })).toEqual(floorOf("example.worker", "credential"))
  })

  test("worker-upload: an inherit binding is credential", () => {
    expect(uploadWith({ bindings: [{ type: "inherit", name: "API_KEY" }] })).toEqual(floorOf("example.worker", "credential"))
  })

  test("worker-upload: a hyperdrive binding is credential", () => {
    expect(uploadWith({ bindings: [{ type: "hyperdrive", name: "DB", id: ACCOUNT }] })).toEqual(floorOf("example.worker", "credential"))
  })

  test("worker-upload: a service binding is sharing", () => {
    expect(uploadWith({ bindings: [{ type: "service", name: "AUTH", service: "auth-worker" }] })).toEqual(floorOf("example.worker", "sharing"))
  })

  test("worker-upload: a Durable Object binding naming another script is sharing, and one of its own classes is not", () => {
    expect(uploadWith({ bindings: [{ type: "durable_object_namespace", name: "ROOMS", class_name: "Room", script_name: "chat-worker" }] })).toEqual(floorOf("example.worker", "sharing"))
    expect(uploadWith({ bindings: [{ type: "durable_object_namespace", name: "ROOMS", class_name: "Room", dispatch_namespace: "tenants" }] })).toEqual(floorOf("example.worker", "sharing"))
    expect(uploadWith({ bindings: [{ type: "durable_object_namespace", name: "ROOMS", class_name: "Room" }] })).toEqual(routine)
  })

  test("worker-upload: an unknown binding type, or a binding it cannot read, is credential", () => {
    for (const bindings of [[{ type: "quantum_link", name: "Q" }], [{ name: "NO_TYPE" }], [{ type: 1, name: "N" }], [{ type: "ai", TYPE: "ai", name: "AI" }], ["ai"], { type: "ai", name: "AI" }]) {
      expect(uploadWith({ bindings }), JSON.stringify(bindings)).toEqual(floorOf("example.worker", "credential"))
    }
  })

  // Every binding type https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/update/
  // lists under metadata.bindings, and what a routine upload holding it is.
  const WORKER_BINDING_TYPES: [type: string, verdict: PolicyFloorReason | "routine", extra: object][] = [
    ["ai", "routine", {}], ["analytics_engine", "routine", { dataset: "events" }], ["assets", "routine", {}], ["browser", "routine", {}], ["data_blob", "routine", { part: "blob.bin" }],
    ["json", "routine", { json: { a: 1 } }], ["plain_text", "routine", { text: "x" }], ["ratelimit", "routine", { namespace_id: "1001", simple: { limit: 10, period: 60 } }], ["text_blob", "routine", { part: "data.txt" }],
    ["version_metadata", "routine", {}], ["wasm_module", "routine", { part: "lib.wasm" }], ["worker_loader", "routine", {}], ["media", "routine", {}], ["workflow", "routine", { workflow_name: "nightly", class_name: "Nightly" }],
    ["durable_object_namespace", "routine", { class_name: "Room" }],
    ["secret_text", "credential", { text: "x" }], ["secret_key", "credential", { algorithm: {}, format: "raw", usages: [] }], ["secrets_store_secret", "credential", { store_id: "s", secret_name: "k" }],
    ["inherit", "credential", {}], ["hyperdrive", "credential", { id: "h" }], ["mtls_certificate", "credential", { certificate_id: "c" }],
    ["send_email", "send", {}],
    ["service", "sharing", { service: "other" }], ["dispatch_namespace", "sharing", { namespace: "tenants" }], ["vpc_service", "sharing", { service_id: "v" }], ["vpc_network", "sharing", { network_id: "cf1:network" }],
    ["d1", "sharing", { id: "d" }], ["r2_bucket", "sharing", { bucket_name: "b" }], ["kv_namespace", "sharing", { namespace_id: "k" }], ["vectorize", "sharing", { index_name: "i" }],
    ["queue", "sharing", { queue_name: "q" }], ["pipelines", "sharing", { pipeline: "p" }], ["ai_search", "sharing", { instance_name: "s" }], ["ai_search_namespace", "sharing", { namespace: "n" }],
    ["k2", "sharing", { stream: "s" }], ["artifacts", "sharing", { namespace: "n" }], ["messaging", "sharing", { namespace: "n" }], ["images", "sharing", {}], ["flagship", "sharing", { app_id: "a" }],
    ["durable_object_namespace", "sharing", { class_name: "Room", script_name: "other" }], ["durable_object_namespace", "sharing", { class_name: "Room", namespace_id: "0123456789abcdef0123456789abcdef" }], ["workflow", "sharing", { workflow_name: "nightly", script_name: "other" }],
  ]

  test.each(WORKER_BINDING_TYPES)("worker-upload: a %s binding is %s", (type, verdict, extra) => {
    expect(uploadWith({ bindings: [{ type, name: "B", ...extra }] })).toEqual(verdict === "routine" ? routine : floorOf("example.worker", verdict))
  })

  test("worker-upload: anything it cannot read exactly is not the entry, and never floor-free routine", () => {
    const meta = metadataPart({ main_module: "index.js" })
    const bodies: [string, Uint8Array, string?, string?][] = [
      ["no metadata", multipart(workerModule)],
      ["two metadata parts", multipart(meta, meta, workerModule)],
      ["metadata named in another case", multipart(part("METADATA", '{"main_module":"index.js"}', "application/json"), workerModule)],
      ["metadata beside one named in another case", multipart(meta, part("Metadata", "{}", "application/json"), workerModule)],
      ["metadata typed as text", multipart(part("metadata", '{"main_module":"index.js"}', "text/plain"), workerModule)],
      ["metadata that is not JSON", multipart(part("metadata", "main_module=index.js", "application/json"), workerModule)],
      ["metadata that is an array", multipart(part("metadata", "[]", "application/json"), workerModule)],
      ["metadata with a repeated key", multipart(part("metadata", '{"main_module":"a.js","main_module":"index.js"}', "application/json"), workerModule)],
      ["metadata after a byte order mark", multipart(part("metadata", '\ufeff{"main_module":"index.js"}', "application/json"), workerModule)],
      ["metadata over 64 KiB", multipart(metadataPart({ main_module: "index.js", note: "x".repeat(64 * 1024) }), workerModule)],
      ["a repeated module name", multipart(meta, workerModule, workerModule)],
      ["module names that fold alike", multipart(meta, workerModule, { ...workerModule, name: "INDEX.js" })],
      ["a module with no type", multipart(meta, part("index.js", "x"))],
      ["a module of another type", multipart(meta, part("run.sh", "x", "application/x-sh"))],
      ["an extended filename", encoded(`--${BOUNDARY}\r\nContent-Disposition: form-data; name="metadata"\r\n\r\n{}\r\n--${BOUNDARY}\r\nContent-Disposition: form-data; name="index.js"; filename*=utf-8''index.js\r\nContent-Type: application/javascript+module\r\n\r\nx\r\n--${BOUNDARY}--`)],
      ["a method override part", multipart(meta, workerModule, part("_method", "DELETE"))],
      ["a part name a splitting parser reads as metadata", multipart(meta, part("metadata; x=1", '{"main_module":"evil.js"}', "application/javascript+module", "evil.js"), workerModule)],
      ["a module filename climbing a directory", multipart(meta, part("index.js", "x", "application/javascript+module", "../index.js"))],
      ["a second boundary", multipart(meta, workerModule), `${UPLOAD_TYPE}; boundary=other`],
      ["multipart/mixed", multipart(meta, workerModule), `multipart/mixed; boundary=${BOUNDARY}`],
      ["a coded body", multipart(meta, workerModule), UPLOAD_TYPE, "gzip"],
    ]
    for (const [label, body, type, coding] of bodies) {
      expect(read(worker(body, type, coding ?? null)), label).toEqual(notCovered)
      expect(evaluatePolicyFloor(worker(body, type, coding ?? null), READERS).action, label).toBe("approve")
    }
    expect(read(worker(json({ main_module: "index.js" }), "application/json"))).toEqual(notCovered)
  })
})

// Outside the pinned corpus: requests that reach an entry's route but must
// never be that entry, read by policyCatalogueVerdict and evaluatePolicyFloor.
describe("the catalogue gate", () => {
  type Route = { catalogue: PolicyCatalogue; method: string; host: string; path: string; body: Uint8Array | null; contentType: string | null }
  const github = policyCatalogueNamed("github") as PolicyCatalogue
  const stripe = policyCatalogueNamed("stripe") as PolicyCatalogue
  const ROUTES: Route[] = [
    { catalogue: github, method: "POST", host: "api.github.com", path: "/repos/alex/vault/issues", body: json({ title: "T" }), contentType: "application/json" },
    { catalogue: github, method: "PATCH", host: "api.github.com", path: "/repos/alex/vault/issues/12", body: json({ state: "closed" }), contentType: "application/json" },
    { catalogue: github, method: "POST", host: "api.github.com", path: "/repos/alex/vault/issues/12/comments", body: json({ body: "C" }), contentType: "application/json" },
    { catalogue: github, method: "PATCH", host: "api.github.com", path: "/repos/alex/vault/issues/comments/42", body: json({ body: "C" }), contentType: "application/json" },
    { catalogue: github, method: "DELETE", host: "api.github.com", path: "/repos/alex/vault/issues/comments/42", body: null, contentType: null },
    { catalogue: stripe, method: "POST", host: "api.stripe.com", path: "/v1/products", body: json({ name: "P" }), contentType: "application/json" },
    { catalogue: stripe, method: "POST", host: "api.stripe.com", path: "/v1/prices/price_1", body: json({ nickname: "N" }), contentType: "application/json" },
    { catalogue: FIXTURE, method: "POST", host: "api.example.test", path: `/accounts/${ACCOUNT}/things`, body: json({ name: "a" }), contentType: "application/json" },
    { catalogue: FIXTURE, method: "PATCH", host: "api.example.test", path: `/accounts/${ACCOUNT}/things/one`, body: json({ name: "a" }), contentType: "application/json" },
    { catalogue: FIXTURE, method: "PUT", host: "api.example.test", path: `/accounts/${ACCOUNT}/blobs/${ACCOUNT}`, body: encoded("bytes"), contentType: "application/octet-stream" },
    { catalogue: FIXTURE, method: "PUT", host: "api.example.test", path: `/accounts/${ACCOUNT}/blobs/${ACCOUNT}/meta`, body: json({ note: "x" }), contentType: "application/octet-stream" },
    { catalogue: FIXTURE, method: "POST", host: "api.example.test", path: `/accounts/${ACCOUNT}/blobs/${ACCOUNT}/touch`, body: null, contentType: null },
    { catalogue: FIXTURE, method: "POST", host: "api.example.test", path: "/repos/alex/vault/issues/12/comments", body: json({ body: "C" }), contentType: "application/json" },
  ]
  const input = (r: Route, patch: { method?: string; search?: string; path?: string; contentType?: string | null } = {}): PolicySafetyInput => ({
    destination: { scheme: "https", host: r.host, port: 443, method: patch.method ?? r.method, path: patch.path ?? r.path, search: patch.search ?? "" },
    body: r.body, contentType: patch.contentType === undefined ? r.contentType : patch.contentType, contentEncoding: null,
  })
  // Never an entry, and floored exactly as a request no catalogue covers.
  const neverEntry = (r: Route, request: PolicySafetyInput, label: string) => {
    expect(policyCatalogueVerdict(request, r.catalogue).entry, label).toBeNull()
    expect(evaluatePolicyFloor(request, r.catalogue), label).toEqual(evaluatePolicyFloor(request, null))
  }

  test("every route here is an entry as sent", () => {
    for (const r of ROUTES) expect(policyCatalogueVerdict(input(r), r.catalogue).entry, `${r.method} ${r.path}`).not.toBeNull()
  })

  test("a method-override query string is never an entry", () => {
    for (const r of ROUTES) {
      for (const search of ["?_method=DELETE", "?_method=delete", "?X-HTTP-Method-Override=DELETE", "?x-http-method=PUT", "?x-method-override=PATCH", "?method=DELETE"]) neverEntry(r, input(r, { search }), `${r.method} ${r.path}${search}`)
    }
  })

  test("a body whose type declares an unread charset is never an entry, of any kind, and charset=utf-8 still is", () => {
    for (const r of ROUTES.filter((r) => r.body !== null)) {
      expect(policyCatalogueVerdict(input(r, { contentType: `${r.contentType}; charset=utf-8` }), r.catalogue).entry, r.path).not.toBeNull()
      for (const charset of ["utf-7", '"UTF-7"', "utf-32", "ucs-2", "x-unknown", ""]) neverEntry(r, input(r, { contentType: `${r.contentType}; charset=${charset}` }), `${r.method} ${r.path} ${charset}`)
    }
  })

  test("OPTIONS is never an entry", () => {
    for (const r of ROUTES) neverEntry(r, input(r, { method: "OPTIONS" }), r.path)
  })

  test("a hand-built destination with an encoded slash, a dot segment or an empty segment is never an entry, and is floor", () => {
    const shapes = (path: string): string[] => {
      const cut = path.lastIndexOf("/")
      const [head, last] = [path.slice(0, cut), path.slice(cut + 1)]
      return [`${head}/a%2F${last}`, `${head}/a%2f${last}`, `${head}/..`, `${head}/.`, `${head}/%2E%2E`, `${head}/%2e%2e`, `${head}//${last}`, `${path}/`, `${head}/../${last}`]
    }
    const gated = ["/v1/prices/a%2Fprice_1", "/v1/prices/..", "/v1/prices/.", "/repos/alex/../issues"]
    expect(gated.every((path) => [...github.entries, ...stripe.entries].some((e) => cataloguePathMatches(e.path, path)))).toBe(true)
    for (const r of ROUTES) {
      for (const path of [...shapes(r.path), ...gated]) {
        const request = input(r, { path })
        expect(policyCatalogueVerdict(request, r.catalogue).entry, path).toBeNull()
        const floor = evaluatePolicyFloor(request, r.catalogue)
        expect(floor.action, path).toBe("approve")
        expect(floor.reasons.some((reason) => reason.startsWith("safety.")), path).toBe(true)
      }
    }
  })
})

describe("the Cloudflare catalogue", () => {
  const ZONE = "fedcba9876543210fedcba9876543210"
  const HEX = "023e105f4ecef8ad9ca31a8372d0c353"
  const UUID = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"
  const A = `/client/v4/accounts/${ACCOUNT}`
  const Z = `/client/v4/zones/${ZONE}`
  const cfRequest = (method: string, path: string, body: Uint8Array | null = null, contentType: string | null = body === null ? null : "application/json"): PolicySafetyInput => ({
    destination: destination(method, `https://api.cloudflare.com${path}`), body, contentType, contentEncoding: null,
  })
  const CLOUDFLARE = policyCatalogueNamed("cloudflare-api-token")
  const upload = multipart(metadataPart({ main_module: "index.js", compatibility_date: "2026-11-01" }), workerModule)
  const record = json({ type: "A", name: "www", content: "192.0.2.1", proxied: true })

  // One request per entry, as the reference documents it.
  const ENTRIES: [id: string, method: string, path: string, body?: Uint8Array, contentType?: string][] = [
    ["cloudflare.worker-upload", "PUT", `${A}/workers/scripts/my-worker`, upload, UPLOAD_TYPE],
    ["cloudflare.worker-version", "POST", `${A}/workers/scripts/my-worker/versions`, upload, UPLOAD_TYPE],
    ["cloudflare.worker-telemetry-query", "POST", `${A}/workers/observability/telemetry/query`, json({ queryId: "errors", timeframe: { from: 1, to: 2 }, view: "events" })],
    ["cloudflare.analytics-engine-sql", "POST", `${A}/analytics_engine/sql`, encoded("SELECT blob1, count() AS n FROM contoso_events GROUP BY blob1"), "text/plain"],
    ["cloudflare.worker-deploy", "POST", `${A}/workers/scripts/my-worker/deployments`, json({ strategy: "percentage", versions: [{ version_id: UUID, percentage: 100 }] })],
    ["cloudflare.worker-route-create", "POST", `${Z}/workers/routes`, json({ pattern: "example.com/*", script: "my-worker" })],
    ["cloudflare.worker-route-update", "PUT", `${Z}/workers/routes/${HEX}`, json({ pattern: "example.com/api/*", script: "my-worker" })],
    ["cloudflare.worker-domain", "PUT", `${A}/workers/domains`, json({ hostname: "app.example.com", service: "my-worker", zone_id: ZONE })],
    ["cloudflare.worker-subdomain", "POST", `${A}/workers/scripts/my-worker/subdomain`, json({ enabled: true })],
    ["cloudflare.worker-schedules", "PUT", `${A}/workers/scripts/my-worker/schedules`, json([{ cron: "*/30 * * * *" }])],
    ["cloudflare.workers-subdomain", "PUT", `${A}/workers/subdomain`, json({ subdomain: "my-team" })],
    ["cloudflare.kv-namespace-create", "POST", `${A}/storage/kv/namespaces`, json({ title: "cache" })],
    ["cloudflare.kv-namespace-rename", "PUT", `${A}/storage/kv/namespaces/${HEX}`, json({ title: "cache-2" })],
    ["cloudflare.kv-value-write", "PUT", `${A}/storage/kv/namespaces/${HEX}/values/user.42`, encoded("any bytes, not JSON"), "application/octet-stream"],
    ["cloudflare.kv-bulk-write", "PUT", `${A}/storage/kv/namespaces/${HEX}/bulk`, json([{ key: "a", value: "1" }, { key: "b", value: "2", expiration_ttl: 3600, metadata: { from: "agent" }, base64: false }])],
    ["cloudflare.kv-bulk-get", "POST", `${A}/storage/kv/namespaces/${HEX}/bulk/get`, json({ keys: ["a", "b"] })],
    ["cloudflare.r2-bucket-create", "POST", `${A}/r2/buckets`, json({ name: "assets" })],
    ["cloudflare.r2-bucket-update", "PATCH", `${A}/r2/buckets/assets`],
    ["cloudflare.r2-cors", "PUT", `${A}/r2/buckets/assets/cors`, json({ rules: [{ allowed: { methods: ["GET"], origins: ["https://example.com"] } }] })],
    ["cloudflare.r2-lock", "PUT", `${A}/r2/buckets/assets/lock`, json({ rules: [] })],
    ["cloudflare.d1-create", "POST", `${A}/d1/database`, json({ name: "app" })],
    ["cloudflare.d1-update", "PATCH", `${A}/d1/database/${UUID}`, json({ read_replication: { mode: "auto" } })],
    ["cloudflare.queue-create", "POST", `${A}/queues`, json({ queue_name: "jobs" })],
    ["cloudflare.queue-update", "PATCH", `${A}/queues/${HEX}`, json({ settings: { delivery_delay: 5 } })],
    ["cloudflare.queue-consumer-create", "POST", `${A}/queues/${HEX}/consumers`, json({ type: "http_pull", settings: { batch_size: 10, visibility_timeout_ms: 6000 } })],
    ["cloudflare.queue-worker-consumer-create", "POST", `${A}/queues/${HEX}/consumers`, json({ script_name: "my-worker", type: "worker" })],
    ["cloudflare.queue-consumer-update", "PUT", `${A}/queues/${HEX}/consumers/${HEX}`, json({ script_name: "my-worker", type: "worker" })],
    ["cloudflare.queue-send", "POST", `${A}/queues/${HEX}/messages`, json({ body: { job: 1 } })],
    ["cloudflare.queue-send-batch", "POST", `${A}/queues/${HEX}/messages/batch`, json({ messages: [{ body: "one" }, { body: "two" }] })],
    ["cloudflare.queue-pull", "POST", `${A}/queues/${HEX}/messages/pull`, json({ batch_size: 10, visibility_timeout_ms: 6000 })],
    ["cloudflare.queue-ack", "POST", `${A}/queues/${HEX}/messages/ack`, json({ acks: [{ lease_id: "x" }], retries: [] })],
    ["cloudflare.pages-domain-update", "PATCH", `${A}/pages/projects/site/domains/www.example.com`],
    ["cloudflare.pages-domain-add", "POST", `${A}/pages/projects/site/domains`, json({ name: "www.example.com" })],
    ["cloudflare.gateway-create", "POST", `${A}/ai-gateway/gateways`, json({ id: "my-gateway", collect_logs: true, cache_ttl: 0, cache_invalidate_on_update: false, rate_limiting_interval: 0, rate_limiting_limit: 0 })],
    ["cloudflare.gateway-dataset-create", "POST", `${A}/ai-gateway/gateways/my-gateway/datasets`, json({ name: "evals", enable: true, filters: [] })],
    ["cloudflare.gateway-dataset-update", "PUT", `${A}/ai-gateway/gateways/my-gateway/datasets/evals`, json({ name: "evals", enable: false, filters: [] })],
    ["cloudflare.gateway-evaluation-create", "POST", `${A}/ai-gateway/gateways/my-gateway/evaluations`, json({ dataset_ids: ["evals"], evaluation_type_ids: ["cost"], name: "weekly" })],
    ["cloudflare.gateway-log-update", "PATCH", `${A}/ai-gateway/gateways/my-gateway/logs/01HZX4M6T2B5K9Q3`, json({ feedback: 1, score: 80 })],
    ["cloudflare.vectorize-create", "POST", `${A}/vectorize/v2/indexes`, json({ name: "docs", config: { dimensions: 768, metric: "cosine" } })],
    ["cloudflare.vectorize-insert", "POST", `${A}/vectorize/v2/indexes/docs/insert`, encoded('{"id":"1","values":[0.1,0.2]}\n{"id":"2","values":[0.3,0.4]}\n'), "application/x-ndjson"],
    ["cloudflare.vectorize-upsert", "POST", `${A}/vectorize/v2/indexes/docs/upsert`, encoded('{"id":"1","values":[0.5,0.6]}\n'), "application/x-ndjson"],
    ["cloudflare.vectorize-query", "POST", `${A}/vectorize/v2/indexes/docs/query`, json({ vector: [0.1, 0.2], topK: 5 })],
    ["cloudflare.vectorize-get", "POST", `${A}/vectorize/v2/indexes/docs/get_by_ids`, json({ ids: ["1", "2"] })],
    ["cloudflare.vectorize-metadata-index", "POST", `${A}/vectorize/v2/indexes/docs/metadata_index/create`, json({ propertyName: "lang", indexType: "string" })],
    ["cloudflare.workflow-deploy", "PUT", `${A}/workflows/nightly`, json({ class_name: "Nightly", script_name: "my-worker" })],
    ["cloudflare.workflow-start", "POST", `${A}/workflows/nightly/instances`, json({ instance_id: "run-1", params: { day: 1 } })],
    ["cloudflare.workflow-event", "POST", `${A}/workflows/nightly/instances/run-1/events/approved`, json({ by: "agent" })],
    ["cloudflare.workflow-status", "PATCH", `${A}/workflows/nightly/instances/run-1/status`, json({ status: "pause" })],
    ["cloudflare.dns-record-create", "POST", `${Z}/dns_records`, record],
    ["cloudflare.dns-cname-create", "POST", `${Z}/dns_records`, json({ type: "CNAME", name: "app", content: "x.pages.dev", proxied: true })],
    ["cloudflare.dns-record-update", "PATCH", `${Z}/dns_records/${HEX}`, record],
  ]

  // One request per floor: a write to it, or a read where its answer holds a
  // secret.
  const FLOORS: [id: string, method: string, path: string][] = [
    ["cloudflare.worker-content", "PUT", `${A}/workers/scripts/my-worker/content`],
    ["cloudflare.worker-settings", "PATCH", `${A}/workers/scripts/my-worker/settings`],
    ["cloudflare.worker-script-settings", "PATCH", `${A}/workers/scripts/my-worker/script-settings`],
    ["cloudflare.worker-secrets", "PUT", `${A}/workers/scripts/my-worker/secrets`],
    ["cloudflare.worker-secrets-bulk", "PATCH", `${A}/workers/scripts/my-worker/secrets-bulk`],
    ["cloudflare.worker-tails", "POST", `${A}/workers/scripts/my-worker/tails`],
    ["cloudflare.workers-account-settings", "PUT", `${A}/workers/account-settings`],
    ["cloudflare.kv-bulk-delete", "POST", `${A}/storage/kv/namespaces/${HEX}/bulk/delete`],
    ["cloudflare.r2-lifecycle", "PUT", `${A}/r2/buckets/assets/lifecycle`],
    ["cloudflare.r2-domains", "POST", `${A}/r2/buckets/assets/domains/custom`],
    ["cloudflare.r2-sippy", "PUT", `${A}/r2/buckets/assets/sippy`],
    ["cloudflare.event-notifications", "PUT", `${A}/event_notifications/r2/assets/configuration/queues/${HEX}`],
    ["cloudflare.d1-query", "POST", `${A}/d1/database/${UUID}/query`],
    ["cloudflare.d1-raw", "POST", `${A}/d1/database/${UUID}/raw`],
    ["cloudflare.d1-import", "POST", `${A}/d1/database/${UUID}/import`],
    ["cloudflare.d1-restore", "POST", `${A}/d1/database/${UUID}/time_travel/restore`],
    ["cloudflare.d1-export", "POST", `${A}/d1/database/${UUID}/export`],
    ["cloudflare.queue-purge", "POST", `${A}/queues/${HEX}/purge`],
    ["cloudflare.pages-project-create", "POST", `${A}/pages/projects`],
    ["cloudflare.pages-project-update", "PATCH", `${A}/pages/projects/site`],
    ["cloudflare.pages-deploy", "POST", `${A}/pages/projects/site/deployments`],
    ["cloudflare.pages-deployment", "GET", `${A}/pages/projects/site/deployments/${UUID}`],
    ["cloudflare.pages-retry", "POST", `${A}/pages/projects/site/deployments/${UUID}/retry`],
    ["cloudflare.pages-rollback", "POST", `${A}/pages/projects/site/deployments/${UUID}/rollback`],
    ["cloudflare.pages-source", "POST", `${A}/pages/projects/site/source`],
    ["cloudflare.queue-messages-purge", "POST", `${A}/queues/${HEX}/messages/purge`],
    ["cloudflare.turnstile-widget-create", "POST", `${A}/challenges/widgets`],
    ["cloudflare.turnstile-widget", "GET", `${A}/challenges/widgets/0x4AAF00AAAABn0R22HWm-YUc`],
    ["cloudflare.turnstile-rotate-secret", "POST", `${A}/challenges/widgets/0x4AAF00AAAABn0R22HWm-YUc/rotate_secret`],
    ["cloudflare.vectorize-delete", "POST", `${A}/vectorize/v2/indexes/docs/delete_by_ids`],
    ["cloudflare.vectorize-metadata-index-delete", "POST", `${A}/vectorize/v2/indexes/docs/metadata_index/delete`],
    ["cloudflare.dns-batch", "POST", `${Z}/dns_records/batch`],
    ["cloudflare.dns-import", "POST", `${Z}/dns_records/import`],
    ["cloudflare.dns-scan-review", "POST", `${Z}/dns_records/scan/review`],
    ["cloudflare.hyperdrive", "PUT", `${A}/hyperdrive/configs/${HEX}`],
    ["cloudflare.secrets-store", "POST", `${A}/secrets_store/stores/${HEX}/secrets`],
    ["cloudflare.zone-email-routing", "POST", `${Z}/email/routing/rules`],
    ["cloudflare.account-email-routing", "POST", `${A}/email/routing/addresses`],
    ["cloudflare.zone-email-sending", "POST", `${Z}/email/sending/subdomains`],
    ["cloudflare.account-email-sending", "POST", `${A}/email/sending/send`],
    ["cloudflare.zone-settings", "PATCH", `${Z}/settings/ssl`],
    ["cloudflare.zone-logpush", "POST", `${Z}/logpush/jobs`],
    ["cloudflare.account-logpush", "POST", `${A}/logpush/jobs`],
    ["cloudflare.account-access", "POST", `${A}/access/apps`],
    ["cloudflare.zone-access", "POST", `${Z}/access/apps`],
    ["cloudflare.tunnels", "PUT", `${A}/cfd_tunnel/${UUID}/configurations`],
    ["cloudflare.tunnel-token", "GET", `${A}/cfd_tunnel/${UUID}/token`],
    ["cloudflare.worker-assets-session", "POST", `${A}/workers/scripts/my-worker/assets-upload-session`],
    ["cloudflare.dispatch-assets-session", "POST", `${A}/workers/dispatch/namespaces/tenants/scripts/customer-1/assets-upload-session`],
    ["cloudflare.workers-assets-upload", "POST", `${A}/workers/assets/upload`],
    ["cloudflare.worker-versions", "GET", `${A}/workers/workers/${HEX}/versions/latest`],
    ["cloudflare.worker-previews", "GET", `${A}/workers/workers/${HEX}/previews/${UUID}/deployments`],
    ["cloudflare.gateways", "GET", `${A}/ai-gateway/gateways`],
    ["cloudflare.gateway", "GET", `${A}/ai-gateway/gateways/my-gateway`],
    ["cloudflare.gateway-custom-providers", "GET", `${A}/ai-gateway/custom-providers/${UUID}`],
    ["cloudflare.gateway-billing", "POST", `${A}/ai-gateway/billing/topup`],
    ["cloudflare.pages-upload-token", "GET", `${A}/pages/projects/site/upload-token`],
    ["cloudflare.workflow-subscribe-token", "GET", `${A}/workflows/nightly/instances/run-1/subscribe/token`],
    ["cloudflare.warp-connector-token", "GET", `${A}/warp_connector/${UUID}/token`],
    ["cloudflare.tunnel-management-token", "POST", `${A}/cfd_tunnel/${UUID}/management`],
    ["cloudflare.account-logpush-jobs", "GET", `${A}/logpush/jobs`],
    ["cloudflare.account-logpush-dataset-jobs", "GET", `${A}/logpush/datasets/audit_logs/jobs`],
    ["cloudflare.zone-logpush-jobs", "GET", `${Z}/logpush/jobs/42`],
    ["cloudflare.zone-logpush-dataset-jobs", "GET", `${Z}/logpush/datasets/http_requests/jobs`],
    ["cloudflare.zone-logpush-edge-jobs", "GET", `${Z}/logpush/edge/jobs`],
    ["cloudflare.stream-live-inputs", "POST", `${A}/stream/live_inputs`],
    ["cloudflare.stream-live-input", "GET", `${A}/stream/live_inputs/${HEX}`],
    ["cloudflare.stream-webhook", "GET", `${A}/stream/webhook`],
    ["cloudflare.stream-keys", "POST", `${A}/stream/keys`],
    ["cloudflare.stream-token", "POST", `${A}/stream/${HEX}/token`],
    ["cloudflare.tsigs", "GET", `${A}/secondary_dns/tsigs/${HEX}`],
    ["cloudflare.account-access-apps", "GET", `${A}/access/apps`],
    ["cloudflare.account-access-app", "GET", `${A}/access/apps/${UUID}`],
    ["cloudflare.account-identity-providers", "GET", `${A}/access/identity_providers`],
    ["cloudflare.account-identity-provider", "GET", `${A}/access/identity_providers/${UUID}`],
    ["cloudflare.account-service-tokens", "POST", `${A}/access/service_tokens`],
    ["cloudflare.account-service-token-rotate", "POST", `${A}/access/service_tokens/${UUID}/rotate`],
    ["cloudflare.zone-access-apps", "GET", `${Z}/access/apps`],
    ["cloudflare.zone-access-app", "GET", `${Z}/access/apps/${UUID}`],
    ["cloudflare.zone-identity-providers", "GET", `${Z}/access/identity_providers`],
    ["cloudflare.zone-identity-provider", "GET", `${Z}/access/identity_providers/${UUID}`],
    ["cloudflare.zone-service-tokens", "POST", `${Z}/access/service_tokens`],
    ["cloudflare.oauth-clients", "POST", `${A}/oauth_clients`],
    ["cloudflare.moq-relays", "POST", `${A}/moq/relays/${HEX}/tokens`],
    ["cloudflare.calls", "POST", `${A}/calls/turn_keys`],
    ["cloudflare.realtime-livestreams", "GET", `${A}/realtime/kit/${UUID}/livestreams/${UUID}`],
    ["cloudflare.realtime-meeting-livestream", "GET", `${A}/realtime/kit/${UUID}/meetings/${UUID}/livestream`],
    ["cloudflare.realtime-meeting-active-livestream", "GET", `${A}/realtime/kit/${UUID}/meetings/${UUID}/active-livestream`],
    ["cloudflare.realtime-meeting-livestreams", "POST", `${A}/realtime/kit/${UUID}/meetings/${UUID}/livestreams`],
    ["cloudflare.realtime-participants", "POST", `${A}/realtime/kit/${UUID}/meetings/${UUID}/participants`],
    ["cloudflare.container-registry-credentials", "POST", `${A}/containers/registries/registry.example.com/credentials`],
    ["cloudflare.device-override-codes", "POST", `${A}/devices/override_codes`],
    ["cloudflare.device-override-code", "GET", `${A}/devices/${UUID}/override_codes`],
    ["cloudflare.registration-override-code", "GET", `${A}/devices/registrations/${UUID}/override_codes`],
    ["cloudflare.dlp-datasets", "POST", `${A}/dlp/datasets`],
    ["cloudflare.ipsec-psk-generate", "POST", `${A}/magic/ipsec_tunnels/${HEX}/psk_generate`],
    ["cloudflare.ipsec-psks", "POST", `${A}/magic/ipsec_tunnels/psk`],
    ["cloudflare.vulnerability-discovery-repos", "POST", `${A}/managed-defense/vulnerability-discovery/repos/${UUID}/token`],
    ["cloudflare.vpc-flows-token", "POST", `${A}/mnm/vpc-flows/token`],
    ["cloudflare.pipeline-sinks", "POST", `${A}/pipelines/v1/sinks`],
    ["cloudflare.r2-temp-credentials", "POST", `${A}/r2/temp-access-credentials`],
    ["cloudflare.artifacts-repos", "POST", `${A}/artifacts/namespaces/team/repos`],
    ["cloudflare.pagerduty-connect", "POST", `${A}/alerting/v3/destinations/pagerduty/connect`],
    ["cloudflare.alert-unsubscribe", "GET", `${A}/alerting/v3/policies/${UUID}/email/unsubscribe`],
    ["cloudflare.images-keys", "GET", `${A}/images/v1/keys`],
    ["cloudflare.custom-hostnames", "GET", `${Z}/custom_hostnames/${HEX}`],
    ["cloudflare.origin-tls-client-auth", "GET", `${Z}/origin_tls_client_auth`],
    ["cloudflare.zaraz", "GET", `${Z}/settings/zaraz/config`],
  ]

  test("is the template's, with eleven areas", () => {
    expect(CLOUDFLARE).toMatchObject({ template: "cloudflare-api-token", version: 2, hosts: ["api.cloudflare.com"] })
    expect(CLOUDFLARE?.areas.map((a) => a.id)).toEqual(["workers", "routes", "kv", "r2", "d1", "queues", "pages", "ai-gateway", "vectorize", "workflows", "dns"])
    expect(TEMPLATES["cloudflare-api-token"]?.binding.paths).toEqual(["/client/v4/**"])
    for (const path of [...(CLOUDFLARE?.entries ?? []), ...(CLOUDFLARE?.floor ?? [])].map((e) => e.path)) expect(path.startsWith("/client/v4/"), path).toBe(true)
  })

  test("has one case below for every entry and every floor", () => {
    expect(ENTRIES.map(([id]) => id).sort()).toEqual((CLOUDFLARE?.entries ?? []).map((e) => e.id).sort())
    expect(FLOORS.map(([id]) => id).sort()).toEqual((CLOUDFLARE?.floor ?? []).map((f) => f.id).sort())
  })

  // Keyed by id: test.each fills a short row's missing values with its callback.
  test.each(ENTRIES.map(([id]) => id))("%s: a documented request is the entry, with no floor", (id) => {
    const [, method, path, body, contentType] = ENTRIES.find(([e]) => e === id)!
    const input = cfRequest(method, path, body ?? null, contentType ?? (body === undefined ? null : "application/json"))
    const verdict = policyCatalogueVerdict(input)
    expect({ floor: verdict.floor, entry: verdict.entry?.id }).toEqual({ floor: [], entry: id })
    expect(evaluatePolicyFloor(input), id).toEqual({ action: "allow", reasons: [] })
    expect(classifyPolicyRequest(input).routeId).toBe(id)
  })

  // Analytics Engine takes its SQL as the raw body, whatever its type, so
  // SQL sent untyped, as text (as fetch sends a string) or as a form (as curl
  // --data sends it) is the entry. Every other body on that path, and SQL
  // text on any other path, asked before the entry and asks as it did.
  const SQL = `${A}/analytics_engine/sql`
  const withoutSql: PolicyCatalogue = { ...CLOUDFLARE!, entries: CLOUDFLARE!.entries.filter((e) => e.id !== "cloudflare.analytics-engine-sql") }
  const asBefore = (input: PolicySafetyInput, label: string): void => {
    expect(policyCatalogueVerdict(input).entry?.id ?? null, label).toBeNull()
    expect(evaluatePolicyFloor(input), label).toEqual(evaluatePolicyFloor(input, withoutSql))
  }

  test.each([
    ["SELECT blob1 AS route, count() AS hits FROM contoso_events WHERE timestamp > NOW() - INTERVAL '1' DAY GROUP BY route ORDER BY hits DESC", null],
    ["SELECT\n  double1 AS ms,\n  blob2 AS status\nFROM contoso_requests\nLIMIT 100;\n", null],
    ["SHOW TABLES", null],
    ["-- slowest routes\nSELECT blob1, quantileWeighted(0.95)(double1, _sample_interval) FROM contoso_requests GROUP BY blob1", "text/plain; charset=utf-8"],
    ["SELECT blob1 FROM contoso_events LIMIT 10", "text/plain;charset=UTF-8"],
    ["SELECT blob1, count() AS n FROM contoso_events GROUP BY blob1", "application/x-www-form-urlencoded"],
    ["\uFEFFSELECT blob1 FROM contoso_events", "text/plain"],
  ])("Analytics Engine SQL %#, untyped, as text/plain or as a form, is the routine entry with no floor", (sql, contentType) => {
    const input = cfRequest("POST", SQL, encoded(sql), contentType)
    expect(policyCatalogueVerdict(input)).toEqual({ floor: [], entry: CLOUDFLARE!.entries.find((e) => e.id === "cloudflare.analytics-engine-sql") ?? null })
    expect(evaluatePolicyFloor(input)).toEqual({ action: "allow", reasons: [] })
    expect(classifyPolicyRequest(input)).toEqual({ effect: "routine", routeId: "cloudflare.analytics-engine-sql", additionalPermission: false })
    expect(evaluatePolicyFloor(input, withoutSql).reasons).toEqual(["safety.body-opaque"])
  })

  test.each([
    ["a JSON body", json({ query: "SELECT 1" }), "application/json"],
    ["an untyped JSON body", json({ sql: "SELECT 1" }), null],
    ["SQL as another text type", encoded("SELECT 1"), "text/csv"],
    ["two statements", encoded("SELECT 1; SELECT 2"), null],
    ["two statements sent as a form", encoded("SELECT 1; SELECT 2"), "application/x-www-form-urlencoded"],
    ["a comment after a semicolon", encoded("SELECT 1; -- note"), "text/plain"],
    ["a method override field", encoded("_method=DELETE"), "text/plain"],
    ["a method override field sent as a form", encoded("_method=DELETE"), "application/x-www-form-urlencoded"],
    ["a form with a charset the checks do not read", encoded("SELECT 1"), "application/x-www-form-urlencoded; charset=utf-7"],
    ["a charset the checks do not read", encoded("SELECT 1"), "text/plain; charset=utf-7"],
    ["a multipart body", encoded("--b\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nSELECT 1\r\n--b--\r\n"), "multipart/form-data; boundary=b"],
    ["an empty body", new Uint8Array(), null],
    ["bytes that are not UTF-8", new Uint8Array([0x53, 0xff]), "text/plain"],
  ])("refusal/%s on the Analytics Engine SQL path asks as it did before the entry", (label, body, contentType) => {
    asBefore(cfRequest("POST", SQL, body, contentType), label)
  })

  test("refusal/an encoded Analytics Engine SQL body asks as it did before the entry", () => {
    asBefore({ ...cfRequest("POST", SQL, encoded("SELECT 1"), "text/plain"), contentEncoding: "gzip" }, "gzip")
  })

  test("refusal/SQL text to any other path asks as it did before the entry", () => {
    for (const path of [`${A}/analytics_engine/sql/extra`, `${A}/analytics_engine`, `${A}/workers/observability/telemetry/query`, `${A}/d1/database/${UUID}/query`, `/client/v4/accounts/not-an-account/analytics_engine/sql`, `${A}/Analytics_Engine/sql`]) {
      for (const contentType of [null, "text/plain"]) asBefore(cfRequest("POST", path, encoded("SELECT 1"), contentType), `${contentType} ${path}`)
    }
    asBefore(cfRequest("PUT", SQL, encoded("SELECT 1"), "text/plain"), "PUT")
    const elsewhere: PolicySafetyInput = { destination: destination("POST", `https://api.example.com${SQL}`), body: encoded("SELECT 1"), contentType: "text/plain", contentEncoding: null }
    expect(evaluatePolicyFloor(elsewhere).reasons).toContain("safety.body-opaque")
  })

  test.each(FLOORS)("%s: always reaches a person, whatever the body", (id, method, path) => {
    for (const body of [null, json({ name: "x" }), encoded("bytes")]) {
      const input = cfRequest(method, path, body, body === null ? null : "application/json")
      const verdict = policyCatalogueVerdict(input)
      expect(verdict.entry, id).toBeNull()
      expect(verdict.floor.map((f) => f.id), id).toContain(id)
      const decision = evaluatePolicyFloor(input)
      expect(decision.action === "approve" && decision.reasons.includes(id), id).toBe(true)
      expect(catalogueFloorReason(id)).toBe(CLOUDFLARE?.floor.find((f) => f.id === id)?.reason ?? null)
    }
  })

  test("a floor holds every write method and spelling of its path, and the tunnel token floor its read", () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) expect(policyCatalogueVerdict(cfRequest(method, `${A}/workers/scripts/my-worker/secrets/API_KEY`)).floor.map((f) => f.id)).toContain("cloudflare.worker-secrets")
    expect(policyCatalogueVerdict(cfRequest("GET", `${A}/workers/scripts/my-worker/secrets`)).floor).toEqual([])
    for (const path of [`${A}/cfd_tunnel/${UUID}/token`, `${A}/cfd_tunnel/${UUID}/TOKEN`, `${A}/cfd_tunnel/${UUID}/%74oken`, `${A}/cfd_tunnel/${UUID}/token/`, `${A}/CFD_TUNNEL/${UUID.toUpperCase()}/token`]) {
      for (const method of ["GET", "HEAD"]) expect(policyCatalogueVerdict(cfRequest(method, path)).floor, `${method} ${path}`).toEqual([{ id: "cloudflare.tunnel-token", reason: "credential" }])
    }
    expect(policyCatalogueVerdict(cfRequest("GET", `${A}/cfd_tunnel/${UUID}`)).floor).toEqual([])
    expect(policyCatalogueVerdict(cfRequest("GET", `${A}/cfd_tunnel/${UUID}/connections`)).floor).toEqual([])
  })

  // Every Pages project and deployment answer holds the project's variables'
  // values, secret ones included, so each request that gets one is floor
  // whole, whatever its body: the floor key table in the PR body is what a
  // relaxation would still have to floor.
  test("a Pages project change is floor (credential) whatever it changes, a production_branch patch included", () => {
    for (const body of [{ production_branch: "release" }, { build_config: { build_command: "curl x | sh" } }, { source: { type: "github" } }, { deployment_configs: { production: { services: { AUTH: { service: "auth" } } } } },
      { deployment_configs: { production: { env_vars: { MODE: { type: "plain_text", value: "prod" } } } } }, { deployment_configs: { production: { compatibility_date: "2026-11-01" } } }]) {
      expect(policyCatalogueVerdict(cfRequest("PATCH", `${A}/pages/projects/site`, json(body))), JSON.stringify(body)).toEqual({ floor: [{ id: "cloudflare.pages-project-update", reason: "credential" }], entry: null })
    }
    expect(policyCatalogueVerdict(cfRequest("POST", `${A}/pages/projects`, json({ name: "site", production_branch: "main" })))).toEqual({ floor: [{ id: "cloudflare.pages-project-create", reason: "credential" }], entry: null })
  })

  test("a Pages deploy is floor (credential), a static-only one, one carrying _worker.js and one whose manifest alone names /_worker.js alike", () => {
    const manifest = part("manifest", JSON.stringify({ "/index.html": "0123456789abcdef0123456789abcdef" }))
    const workerManifest = part("manifest", JSON.stringify({ "/_worker.js": "fedcba9876543210fedcba9876543210" }))
    for (const body of [multipart(manifest, part("branch", "main")), multipart(manifest, part("_worker.js", "export default {}", "application/javascript+module", "_worker.js")), multipart(workerManifest)]) {
      const input = cfRequest("POST", `${A}/pages/projects/site/deployments`, body, UPLOAD_TYPE)
      expect(policyCatalogueVerdict(input)).toEqual({ floor: [{ id: "cloudflare.pages-deploy", reason: "credential" }], entry: null })
      expect(evaluatePolicyFloor(input).reasons).toContain("cloudflare.pages-deploy")
    }
  })

  test("reading a Pages project or deployment is floor (credential), and reading its domains is not", () => {
    for (const [id, path] of [["cloudflare.pages-project-create", `${A}/pages/projects`], ["cloudflare.pages-project-update", `${A}/pages/projects/site`], ["cloudflare.pages-deploy", `${A}/pages/projects/site/deployments`], ["cloudflare.pages-deployment", `${A}/pages/projects/site/deployments/${UUID}`]] as const) {
      for (const method of ["GET", "HEAD"]) expect(policyCatalogueVerdict(cfRequest(method, path)).floor, `${method} ${path}`).toEqual([{ id, reason: "credential" }])
    }
    expect(policyCatalogueVerdict(cfRequest("GET", `${A}/pages/projects/site/domains`)).floor).toEqual([])
    expect(classifyPolicyRequest(cfRequest("GET", `${A}/pages/projects/site/domains`)).effect).toBe("read")
  })

  test("AI gateway floor keys make a create floor, at any depth and in any case: logs and traces sent out are persistence, a Stripe key credential", () => {
    const create = (body: unknown) => policyCatalogueVerdict(cfRequest("POST", `${A}/ai-gateway/gateways`, json({ collect_logs: true, ...(body as object) }))).floor
    for (const key of ["logpush", "logpush_public_key", "LOGPUSH", "otel", "Otel"]) expect(create({ [key]: true }), key).toEqual([{ id: "cloudflare.gateway-create:persistence", reason: "persistence" }])
    expect(create({ otel: [{ url: "https://otel.example.com", authorization: "Bearer x" }] })).toEqual([{ id: "cloudflare.gateway-create:persistence", reason: "persistence" }])
    expect(create({ settings: { stripe: { authorization: "sk_live_x" } } })).toEqual([{ id: "cloudflare.gateway-create:credential", reason: "credential" }])
  })

  // https://developers.cloudflare.com/api/resources/ai_gateway/methods/update/:
  // the answer holds the gateway's otel authorization and Stripe key, stored
  // earlier, whatever the body sends, and so does every GET of a gateway.
  test("an AI gateway update is floor (credential) whatever it changes, and reading the gateways is too", () => {
    expect(policyCatalogueVerdict(cfRequest("PUT", `${A}/ai-gateway/gateways/my-gateway`, json({ collect_logs: false, cache_ttl: 60, cache_invalidate_on_update: false, rate_limiting_interval: 0, rate_limiting_limit: 0 })))).toEqual({ floor: [{ id: "cloudflare.gateway", reason: "credential" }], entry: null })
    expect(CLOUDFLARE?.entries.some((e) => e.id === "cloudflare.gateway-update")).toBe(false)
    for (const [id, path] of [["cloudflare.gateways", `${A}/ai-gateway/gateways`], ["cloudflare.gateway", `${A}/ai-gateway/gateways/my-gateway`]] as const) {
      for (const method of ["GET", "HEAD"]) expect(policyCatalogueVerdict(cfRequest(method, path)).floor, `${method} ${path}`).toEqual([{ id, reason: "credential" }])
    }
  })

  // The answers these floors hold back are documented on each route's page
  // under https://developers.cloudflare.com/api/resources/ (the PR body
  // lists them), and a sibling read whose answer holds no secret stays an
  // ordinary read.
  test("a read next to a secret-bearing one, whose answer holds no secret, stays an ordinary read", () => {
    for (const path of [`${A}/stream/live_inputs`, `${A}/access/apps/${UUID}/policies`, `${A}/access/groups`, `${A}/logpush/datasets/audit_logs/fields`, `${Z}/logpush/datasets/http_requests/fields`,
      `${A}/ai-gateway/gateways/my-gateway/datasets`, `${A}/ai-gateway/gateways/my-gateway/logs`, `${A}/pcaps`, `${A}/pcaps/${HEX}`, `${A}/pcaps/${HEX}/download`, `${A}/realtime/kit/${UUID}/meetings`, `${A}/realtime/kit/${UUID}/meetings/${UUID}`, `${A}/realtime/kit/${UUID}/meetings/${UUID}/participants`, `${A}/dlp/email/account_mapping`, `${A}/workers/workers/${HEX}`, `${A}/cfd_tunnel/${UUID}/management`,
      `${A}/hyperdrive/configs/${HEX}`, `${A}/dlp/datasets`, `${Z}/settings/ssl`]) {
      const input = cfRequest("GET", path)
      expect(policyCatalogueVerdict(input).floor, path).toEqual([])
      expect(evaluatePolicyFloor(input), path).toEqual({ action: "allow", reasons: [] })
      expect(classifyPolicyRequest(input).effect, path).toBe("read")
    }
  })

  test("a write whose answer holds a new secret once is floor (credential): an Access service token, created or rotated", () => {
    for (const path of [`${A}/access/service_tokens`, `${A}/access/service_tokens/${UUID}/rotate`, `${Z}/access/service_tokens`]) {
      const reasons = policyCatalogueVerdict(cfRequest("POST", path, json({ name: "ci" }))).floor.map((f) => f.reason)
      expect(reasons, path).toContain("credential")
    }
  })

  test("a floor on a secret-bearing read holds GET and HEAD in any spelling of its path", () => {
    for (const path of [`${A}/stream/live_inputs/${HEX}`, `${A}/stream/live_inputs/${HEX}/outputs`, `${A}/STREAM/live_inputs/${HEX}/`, `${A}/stream/%6cive_inputs/${HEX}`]) {
      for (const method of ["GET", "HEAD"]) expect(policyCatalogueVerdict(cfRequest(method, path)).floor, `${method} ${path}`).toEqual([{ id: "cloudflare.stream-live-input", reason: "credential" }])
    }
  })

  test("creating a CNAME record is destructive, since it can prove a domain or authorise mail with no _ label, and an A or AAAA record stays routine", () => {
    const create = (body: unknown) => classifyPolicyRequest(cfRequest("POST", `${Z}/dns_records`, json(body)))
    expect(create({ type: "CNAME", name: "em1234", content: "u1234.wl.sendgrid.net" })).toEqual({ effect: "destructive", routeId: "cloudflare.dns-cname-create", additionalPermission: false })
    expect(create({ type: "cname", name: "app", content: "x.pages.dev" }).routeId).toBe("cloudflare.dns-cname-create")
    for (const type of ["A", "AAAA"]) expect(create({ type, name: "www", content: type === "A" ? "192.0.2.1" : "2001:db8::1" }), type).toEqual({ effect: "routine", routeId: "cloudflare.dns-record-create", additionalPermission: false })
    expect(policyCatalogueVerdict(cfRequest("POST", `${Z}/dns_records`, json({ type: "CNAME", name: "_dmarc", content: "x" })))).toEqual({ floor: [{ id: "cloudflare.dns-cname-create:persistence", reason: "persistence" }], entry: null })
  })

  test("a DNS record other than A, AAAA or CNAME, or under a _ label, is floor on create and update", () => {
    for (const [method, path] of [["POST", `${Z}/dns_records`], ["PUT", `${Z}/dns_records/${HEX}`], ["PATCH", `${Z}/dns_records/${HEX}`]] as const) {
      for (const body of [{ type: "TXT", name: "@", content: "v=spf1 -all" }, { type: "MX", name: "@", content: "mx.example.com", priority: 10 }, { type: "CNAME", name: "_acme-challenge", content: "x" }, { content: "192.0.2.1" }]) {
        const id = method !== "POST" ? "cloudflare.dns-record-update" : body.type === "CNAME" ? "cloudflare.dns-cname-create" : "cloudflare.dns-record-create"
        expect(policyCatalogueVerdict(cfRequest(method, path, json(body))), `${method} ${JSON.stringify(body)}`).toEqual({ floor: [{ id: `${id}:persistence`, reason: "persistence" }], entry: null })
      }
    }
  })

  test("data entries take stored bytes of any type, but not a method override, an unread charset or a content coding", () => {
    const value = `${A}/storage/kv/namespaces/${HEX}/values/user.42`
    const insert = `${A}/vectorize/v2/indexes/docs/insert`
    for (const [body, type] of [[encoded("plain text"), "text/plain"], [new Uint8Array([0, 255, 1, 254]), "application/octet-stream"], [json({ any: "json" }), "application/json"], [multipart(part("value", "v"), part("metadata", "{}")), UPLOAD_TYPE]] as const) {
      expect(policyCatalogueVerdict(cfRequest("PUT", value, body, type)).entry?.id, type).toBe("cloudflare.kv-value-write")
    }
    expect(policyCatalogueVerdict(cfRequest("PUT", value, encoded("_method=DELETE"), "application/x-www-form-urlencoded")).entry).toBeNull()
    expect(policyCatalogueVerdict(cfRequest("PUT", value, json({ _method: "DELETE" }), "application/json")).entry).toBeNull()
    expect(policyCatalogueVerdict(cfRequest("PUT", value, encoded("x"), "text/plain; charset=utf-7")).entry).toBeNull()
    expect(policyCatalogueVerdict({ ...cfRequest("POST", insert, encoded('{"id":"1","values":[1]}\n'), "application/x-ndjson"), contentEncoding: "gzip" }).entry).toBeNull()
    expect(policyCatalogueVerdict(cfRequest("POST", insert, encoded("not json at all"), "application/x-ndjson")).entry?.id).toBe("cloudflare.vectorize-insert")
  })

  test("a data entry's floor keys are read from a JSON body, and a body that is not JSON is never that entry", () => {
    const meta = `/accounts/${ACCOUNT}/blobs/${"a".repeat(32)}/meta`
    expect(policyCatalogueVerdict(request("PUT", meta, json({ nested: { ENV_VARS: 1 } }), "application/octet-stream"), FIXTURE)).toEqual({ floor: [{ id: "example.blob-meta:credential", reason: "credential" }], entry: null })
    for (const body of [encoded("env_vars"), new Uint8Array([0xff, 0xfe, 0x00]), encoded('{"env_vars":1,"env_vars":2}')]) {
      expect(policyCatalogueVerdict(request("PUT", meta, body, "application/octet-stream"), FIXTURE)).toEqual({ floor: [], entry: null })
    }
    expect(policyCatalogueVerdict(request("PUT", meta, json({ plain: 1 }), "application/octet-stream"), FIXTURE).entry?.id).toBe("example.blob-meta")
  })

  test("the KV bulk and cron readers take only the documented array, and anything else is not the entry", () => {
    const bulk = `${A}/storage/kv/namespaces/${HEX}/bulk`
    const schedules = `${A}/workers/scripts/my-worker/schedules`
    for (const body of [[], [{ key: "a" }], [{ key: "a", value: 1 }], [{ key: "a", value: "1", KEY: "b" }], [{ key: "a", value: "1", _method: "DELETE" }], [{ key: "a", value: "1" }, "x"], { key: "a", value: "1" }]) {
      expect(policyCatalogueVerdict(cfRequest("PUT", bulk, json(body))), JSON.stringify(body)).toEqual({ floor: [], entry: null })
    }
    expect(policyCatalogueVerdict(cfRequest("PUT", bulk, encoded('[{"key":"a","value":"1","key":"b"}]'))).entry).toBeNull()
    expect(policyCatalogueVerdict(cfRequest("PUT", bulk, json([{ key: "a", value: "1" }]), "text/plain")).entry).toBeNull()
    expect(policyCatalogueVerdict(cfRequest("PUT", bulk, json([{ key: "a", value: "x".repeat(64 * 1024) }]))).entry).toBeNull()
    for (const body of [[{ cron: 5 }], [{ cron: "* * * * *", script: "x" }], [], { cron: "* * * * *" }]) {
      expect(policyCatalogueVerdict(cfRequest("PUT", schedules, json(body))), JSON.stringify(body)).toEqual({ floor: [], entry: null })
    }
  })

  test("a Worker upload with a secret binding is floor on every upload route, and an unreadable one is never routine", () => {
    const secret = multipart(metadataPart({ main_module: "index.js", bindings: [{ type: "secret_text", name: "API_KEY", text: "x" }] }), workerModule)
    for (const [id, method, path] of [["cloudflare.worker-upload", "PUT", `${A}/workers/scripts/my-worker`], ["cloudflare.worker-version", "POST", `${A}/workers/scripts/my-worker/versions`]] as const) {
      expect(policyCatalogueVerdict(cfRequest(method, path, secret, UPLOAD_TYPE))).toEqual({ floor: [{ id: `${id}:credential`, reason: "credential" }], entry: null })
      const unreadable = cfRequest(method, path, multipart(workerModule), UPLOAD_TYPE)
      expect(policyCatalogueVerdict(unreadable)).toEqual({ floor: [], entry: null })
      expect(evaluatePolicyFloor(unreadable).reasons).toContain("safety.batch")
    }
  })

  test("a full Worker upload is destructive, since it replaces live code at once, and a version upload stays routine", () => {
    expect(classifyPolicyRequest(cfRequest("PUT", `${A}/workers/scripts/my-worker`, upload, UPLOAD_TYPE))).toEqual({ effect: "destructive", routeId: "cloudflare.worker-upload", additionalPermission: false })
    expect(classifyPolicyRequest(cfRequest("POST", `${A}/workers/scripts/my-worker/versions`, upload, UPLOAD_TYPE)).effect).toBe("routine")
  })

  test("a content-only Worker upload is floor (credential) whatever it holds, since it keeps every binding, secrets included", () => {
    for (const body of [upload, multipart(workerModule)]) {
      const input = cfRequest("PUT", `${A}/workers/scripts/my-worker/content`, body, UPLOAD_TYPE)
      expect(policyCatalogueVerdict(input)).toEqual({ floor: [{ id: "cloudflare.worker-content", reason: "credential" }], entry: null })
      expect(evaluatePolicyFloor(input).reasons).toContain("cloudflare.worker-content")
    }
  })

  test("a queue consumer update is destructive, since it can point the queue's messages at another Worker", () => {
    expect(classifyPolicyRequest(cfRequest("PUT", `${A}/queues/${HEX}/consumers/${HEX}`, json({ script_name: "other-worker", type: "worker" })))).toEqual({ effect: "destructive", routeId: "cloudflare.queue-consumer-update", additionalPermission: false })
  })

  test("a Workflow deploy is destructive, since it can point the Workflow at another script", () => {
    expect(classifyPolicyRequest(cfRequest("PUT", `${A}/workflows/nightly`, json({ class_name: "Nightly", script_name: "other-worker" })))).toEqual({ effect: "destructive", routeId: "cloudflare.workflow-deploy", additionalPermission: false })
  })

  test("adding a queue consumer that names a Worker is destructive, and only a pull consumer naming none is routine", () => {
    const add = (body: unknown) => classifyPolicyRequest(cfRequest("POST", `${A}/queues/${HEX}/consumers`, json(body)))
    for (const body of [{ script_name: "other-worker", type: "worker" }, { type: "http_pull", script_name: "other-worker" }, { type: "http_pull", settings: { Script_Name: "x" } }, { type: "worker" }, {}, { type: "http_pull", TYPE: "worker" }]) {
      expect(add(body), JSON.stringify(body)).toEqual({ effect: "destructive", routeId: "cloudflare.queue-worker-consumer-create", additionalPermission: false })
    }
    for (const body of [{ type: "http_pull" }, { type: "HTTP_PULL", dead_letter_queue: "dlq", settings: { max_retries: 3 } }]) {
      expect(add(body), JSON.stringify(body)).toEqual({ effect: "routine", routeId: "cloudflare.queue-consumer-create", additionalPermission: false })
    }
  })

  // Every Turnstile widget answer but the list holds the widget's secret
  // (https://developers.cloudflare.com/api/resources/turnstile/subresources/widgets/),
  // so nothing in Turnstile is an entry and there is no Turnstile area.
  test("Turnstile is no area: creating, changing and reading a widget are floor (credential), and the widget list is an ordinary read", () => {
    expect(CLOUDFLARE?.areas.some((a) => a.id === "turnstile")).toBe(false)
    expect(CLOUDFLARE?.entries.some((e) => e.path.includes("/challenges/"))).toBe(false)
    const widget = `${A}/challenges/widgets/0x4AAF00AAAABn0R22HWm-YUc`
    for (const [method, path, id] of [["POST", `${A}/challenges/widgets`, "cloudflare.turnstile-widget-create"], ["PUT", widget, "cloudflare.turnstile-widget"], ["GET", widget, "cloudflare.turnstile-widget"], ["HEAD", widget, "cloudflare.turnstile-widget"]] as const) {
      const body = method === "POST" || method === "PUT" ? json({ domains: ["example.com"], mode: "managed", name: "login" }) : null
      expect(policyCatalogueVerdict(cfRequest(method, path, body)), `${method} ${path}`).toEqual({ floor: [{ id, reason: "credential" }], entry: null })
    }
    const list = cfRequest("GET", `${A}/challenges/widgets`)
    expect(policyCatalogueVerdict(list)).toEqual({ floor: [], entry: null })
    expect(evaluatePolicyFloor(list)).toEqual({ action: "allow", reasons: [] })
    expect(classifyPolicyRequest(list).effect).toBe("read")
  })

  test("a route next to an entry is not that entry", () => {
    for (const [method, path] of [
      ["POST", `${A}/workers/scripts/my-worker`], ["PUT", `${A}/workers/scripts/my-worker/versions`], ["PUT", `${A}/storage/kv/namespaces/${HEX}/values/a:b`], ["PUT", `${A}/d1/database/not-a-uuid`],
      ["PUT", `${A}/r2/buckets/assets/objects/file.txt`], ["POST", `${A}/workflows/nightly/instances/batch`], ["POST", `${A}/pages/projects/site/deployments/${UUID}/tails`],
    ] as const) {
      expect(policyCatalogueVerdict(cfRequest(method, path, json({ name: "x" }))).entry, `${method} ${path}`).toBeNull()
    }
  })
})

describe("the Vercel and Neon outlines", () => {
  test("are structure only: no host or template finds them, so nothing is classified, floored or granted from them", () => {
    expect(POLICY_CATALOGUE_OUTLINES.map((c) => [c.template, c.hosts])).toEqual([["vercel", ["api.vercel.com"]], ["neon", ["console.neon.tech"]]])
    for (const c of POLICY_CATALOGUE_OUTLINES) {
      expect(policyCatalogueNamed(c.template)).toBeNull()
      for (const host of c.hosts) expect(policyCatalogueFor(host)).toBeNull()
      expect(POLICY_CATALOGUES.some((r) => r.template === c.template || r.hosts.some((h) => c.hosts.includes(h)))).toBe(false)
    }
    const deploy = { destination: destination("POST", "https://api.vercel.com/v13/deployments"), body: json({ name: "site", env: { A: "b" } }), contentType: "application/json", contentEncoding: null }
    expect(policyCatalogueVerdict(deploy)).toEqual({ floor: [], entry: null })
    expect(classifyPolicyRequest(deploy).routeId).toBeNull()
  })

  test("name the design's areas, floor keys and floors", () => {
    const [vercel, neon] = POLICY_CATALOGUE_OUTLINES
    expect(vercel?.areas.map((a) => a.id)).toEqual(["deployments", "projects", "domains", "edge-config"])
    expect(vercel?.entries.find((e) => e.id === "vercel.deployment-create")?.floorKeys).toEqual({ env: "credential", build: "credential" })
    expect(vercel?.entries.filter((e) => e.area === "domains").every((e) => e.effect === "destructive")).toBe(true)
    expect(neon?.areas.map((a) => a.id)).toEqual(["branches", "computes", "databases"])
    expect(neon?.entries.find((e) => e.id === "neon.branch-create")?.floorKeys).toEqual({ endpoints: "credential" })
    expect(neon?.floor.map((f) => [f.id, f.reason])).toEqual([["neon.branch-restore", "destructive"], ["neon.roles", "credential"], ["neon.project-create", "credential"]])
    expect(cataloguePathMatches("/{v}/projects/{name}", "/v9/projects/site")).toBe(true)
    expect(cataloguePathMatches("/{v}/projects/{name}", "/v100/projects/site")).toBe(false)
  })
})
