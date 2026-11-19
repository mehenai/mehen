// Requests to the GitHub and Stripe catalogue routes and their neighbours,
// every method, body and content type crossed, so a test can hold the
// answers the classifier, the floor and the scope check give them to those
// of mehen-policy-safety/v4, before the catalogues moved to
// policy-catalogue.ts.
import { parseDestination, type Destination } from "../src/binding.ts"
import type { PolicyRouteScope } from "../src/policy-mode.ts"
import type { PolicySafetyInput } from "../src/policy-safety.ts"

const encoded = (text: string): Uint8Array => new TextEncoder().encode(text)
const json = (value: unknown): Uint8Array => encoded(JSON.stringify(value))

const GITHUB_PATHS = [
  "/repos/alex/vault/issues", "/repos/alex/vault/issues/12", "/repos/alex/vault/issues/12/comments", "/repos/alex/vault/issues/comments/42",
  "/repos/foreign-1/vault/issues", "/repos/_bad/vault/issues/12", "/repos/a.b/vault/issues/12/comments", "/repos/-x/vault/issues",
  "/repos/alex/.github/issues/12", "/repos/alex/vault_x/issues/comments/42", "/repos/alex/a:b/issues", "/repos/alex/a~b/issues/12",
  "/repos/alex/vault/issues/0", "/repos/alex/vault/issues/012", "/repos/alex/vault/issues/x/comments", "/repos/alex/vault/issues/comments/comments",
  "/repos/alex/vault/issues/comments", "/repos/alex/vault/issues/12/comments/1", "/repos/alex/vault/issues/12/extra",
  "/repos/alex/vault/issues/", "/repos/alex/vault//issues", "/repositories/123/issues", "/repositories/123/issues/12/comments",
  "/repos/alex/vault/pulls", "/repos/alex/payments-email/issues/42/comments", "/repos/alex/vault/issues/12?per_page=1",
  "/repos/alex/vault/hooks", "/repos/alex/vault", "/repos/alex/vault/issues/comments/42?x=1", "/REPOS/alex/vault/issues",
]
const STRIPE_PATHS = [
  "/v1/products", "/v1/products/prod_1", "/v1/prices", "/v1/prices/price_1", "/v1/products/prod_1/extra", "/v1/products/_x",
  "/v1/products/a:b", "/v1/products/", "/v1/customers", "/v1/charges", "/v1/products?expand=x", "/v1/prices/price_1?x=1", "/v2/products",
]
const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
const BODIES: [string, Uint8Array | null, string | null, string | null][] = [
  ["none", null, null, null],
  ["none, multipart type", null, "multipart/form-data; boundary=a", null],
  ["none, gzip", null, null, "gzip"],
  ["title", json({ title: "T" }), "application/json", null],
  ["title and body", json({ title: "T", body: "B" }), "application/json", null],
  ["state", json({ state: "closed" }), "application/json", null],
  ["bad state", json({ state: "locked" }), "application/json", null],
  ["comment", json({ body: "C" }), "application/json", null],
  ["comment untyped", json({ body: "C" }), null, null],
  ["comment as text", json({ body: "C" }), "text/plain", null],
  ["comment as multipart", json({ body: "C" }), "multipart/form-data; boundary=a", null],
  ["comment gzip", json({ body: "C" }), "application/json", "gzip"],
  ["comment identity", json({ body: "C" }), "application/json", "identity"],
  ["comment with an HTTP line", json({ body: "C\nPOST /x HTTP/1.1\n" }), "application/json", null],
  ["comment and owner", json({ body: "C", owner: "foreign" }), "application/json", null],
  ["empty object", json({}), "application/json", null],
  ["title not a string", json({ title: 1 }), "application/json", null],
  ["array", json([{ body: "C" }]), "application/json", null],
  ["duplicate key", encoded('{"body":"a","body":"b"}'), "application/json", null],
  ["method override", json({ _method: "DELETE", body: "C" }), "application/json", null],
  ["name", json({ name: "Catalogue item" }), "application/json", null],
  ["form", encoded("name=x"), "application/x-www-form-urlencoded", null],
  ["empty bytes", new Uint8Array(), "application/json", null],
  ["oversized", json({ body: "x".repeat(65 * 1024) }), "application/json", null],
]

// The paths parseDestination refuses, for every method, so the corpus has
// no request for them. Any other path it refuses is a mistake in the corpus.
const UNPARSED_PATHS = new Set(["api.github.com/repos/alex/vault//issues"])

export type CatalogueCorpusCase = { label: string; input: PolicySafetyInput }

function destination(method: string, host: string, path: string): Destination | null {
  const parsed = parseDestination(method, `https://${host}${path}`)
  return parsed.ok ? parsed.destination : null
}

export function catalogueCorpus(): CatalogueCorpusCase[] {
  const cases: CatalogueCorpusCase[] = []
  for (const [host, paths] of [["api.github.com", GITHUB_PATHS], ["api.stripe.com", STRIPE_PATHS]] as const) {
    for (const path of paths) {
      for (const method of METHODS) {
        const d = destination(method, host, path)
        if ((d === null) !== UNPARSED_PATHS.has(`${host}${path}`)) throw new Error(`Corpus path ${method} ${host}${path} ${d === null ? "does not parse" : "parses"}`)
        if (d === null) continue
        for (const [name, body, contentType, contentEncoding] of BODIES) cases.push({ label: `${method} ${host}${path} ${name}`, input: { destination: d, body, contentType, contentEncoding } })
      }
    }
  }
  return cases
}

const github = (path: string, anchorPath: string, methods: PolicyRouteScope["methods"], basis: PolicyRouteScope["basis"] = "reviewed"): PolicyRouteScope => ({ host: "api.github.com", methods, path, anchorPath, basis })
const stripe = (path: string, anchorPath: string, methods: PolicyRouteScope["methods"], basis: PolicyRouteScope["basis"] = "reviewed"): PolicyRouteScope => ({ host: "api.stripe.com", methods, path, anchorPath, basis })

// Window scopes whose review rests on the GitHub and Stripe catalogues.
export const CATALOGUE_CORPUS_SCOPES: PolicyRouteScope[] = [
  github("/repos/alex/*/issues/**", "/repos/alex/vault/issues/comments/42", ["POST", "PATCH", "DELETE"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues", ["POST"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues/12", ["PATCH"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues/12/comments", ["POST"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues/comments/not-numeric", ["PATCH"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues/12/extra", ["POST"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues/12", ["GET"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues/12", ["PUT"]),
  github("/repos/_bad/vault/issues/**", "/repos/_bad/vault/issues/12", ["PATCH"]),
  github("/repos/alex/vault/issues/**", "/repos/alex/vault/issues/12", ["PATCH"], "unreviewed"),
  github("/repositories/123/issues/**", "/repositories/123/issues/12/comments", ["POST"], "unreviewed"),
  stripe("/v1/products/**", "/v1/products", ["POST"]),
  stripe("/v1/prices/**", "/v1/prices/price_1", ["POST"]),
  stripe("/v1/products/**", "/v1/products", ["POST", "PATCH"]),
  stripe("/v1/**", "/v1/products", ["POST"], "unreviewed"),
]
// The scope each request's widening eligibility is asked against, one per
// host.
export const CATALOGUE_CORPUS_WINDOWS: PolicyRouteScope[] = [CATALOGUE_CORPUS_SCOPES[0]!, CATALOGUE_CORPUS_SCOPES[11]!]
