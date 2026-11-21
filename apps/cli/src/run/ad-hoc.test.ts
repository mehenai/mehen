import { describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"
import { CliError } from "../errors.ts"
import { VaultApiError } from "../vault-api.ts"
import { type AdHocItem, checkAdHocConflicts, checkItemSpecs, constrainableHost, hostsOverlap, parseItemSpec, resolveAdHocItems } from "./ad-hoc.ts"
import { CommandError } from "./deps.ts"
import { FakeVaultApi, itemDescription } from "./fake-vault-api.ts"

function apiDescribing(slug: string, answer: () => unknown): FakeVaultApi {
  return new FakeVaultApi().on("GET", `/v1/items/${slug}`, answer)
}

async function refusal(promise: Promise<unknown>): Promise<CommandError | CliError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof CommandError || error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

describe("--item specs", () => {
  test("a slug, optionally with a variable name", () => {
    expect(parseItemSpec("openai")).toEqual({ item: "openai", variable: null })
    expect(parseItemSpec("openai=MY_KEY")).toEqual({ item: "openai", variable: "MY_KEY" })
    expect(parseItemSpec("gh=_x9")).toEqual({ item: "gh", variable: "_x9" })
  })

  test("a variable that is not an environment variable name, or a bad slug, is a usage error", () => {
    for (const text of ["openai=1KEY", "openai=MY-KEY", "openai=", "openai=A B", "openai=A=B", "Open", "=KEY", "a"]) {
      expect(() => parseItemSpec(text), text).toThrow(CliError)
    }
    expect(() => parseItemSpec("openai=1KEY")).toThrow("is not an environment variable name")
  })

  test("the same item twice is a usage error", () => {
    expect(() => checkItemSpecs([{ item: "openai", variable: null }, { item: "openai", variable: "B" }])).toThrow("--item openai is given twice")
  })
})

describe("hosts the run CA can hold exactly", () => {
  test("exact names, wildcards over two or more labels, and IP addresses", () => {
    for (const host of ["api.openai.com", "localhost", "*.openai.azure.com", "*.example.co", "10.1.2.3", "[::1]", "::1", "xn--bcher-kva.example"]) expect(constrainableHost(host), host).toBe(true)
  })

  test("a wildcard over a top-level domain, a bare or inner wildcard, a port, upper case or anything else is refused", () => {
    for (const host of ["*.com", "*", "*.*.example.com", "api.*.example.com", "api.openai.com:443", "API.openai.com", "-bad.example.com", "a..example.com", "", "https://api.openai.com"]) {
      expect(constrainableHost(host), host).toBe(false)
    }
  })

  test("overlap: equal hosts, and a wildcard over a host or a deeper wildcard; never the wildcard's apex", () => {
    expect(hostsOverlap("api.openai.com", "API.openai.com")).toBe(true)
    expect(hostsOverlap("*.openai.com", "api.openai.com")).toBe(true)
    expect(hostsOverlap("api.openai.com", "*.openai.com")).toBe(true)
    expect(hostsOverlap("*.openai.com", "*.eu.openai.com")).toBe(true)
    expect(hostsOverlap("*.openai.com", "*.openai.com")).toBe(true)
    expect(hostsOverlap("*.openai.com", "openai.com")).toBe(false)
    expect(hostsOverlap("api.openai.com", "api.anthropic.com")).toBe(false)
  })
})

describe("conflicts", () => {
  const item = (slug: string, variable: string, hosts: string[]): AdHocItem => ({ item: slug, variable, hosts, standIn: "jvph" })

  test("a variable the manifest declares is refused", () => {
    expect(() => checkAdHocConflicts([item("openai", "OPENAI_API_KEY", ["api.openai.com"])], ["OPENAI_API_KEY"], [])).toThrow("which this checkout's mehen.toml also declares")
  })

  test("two items setting one variable, or bound to overlapping hosts, are refused", () => {
    expect(() => checkAdHocConflicts([item("a", "K", ["a.example.com"]), item("b", "K", ["b.example.com"])], [], [])).toThrow("both set K")
    expect(() => checkAdHocConflicts([item("a", "A", ["*.example.com"]), item("b", "B", ["api.example.com"])], [], [])).toThrow("are both bound to")
  })

  test("a host the project's run already intercepts is refused", () => {
    expect(() => checkAdHocConflicts([item("a", "A", ["api.openai.com"])], [], ["*.openai.com"])).toThrow("which this project's run already intercepts")
  })
})

describe("resolveAdHocItems", () => {
  test("the template's variable, the hosts as the vault gave them, and a fresh stand-in with the item's prefix each run", async () => {
    const api = apiDescribing("openai", () => itemDescription())
    const [first] = await resolveAdHocItems(api, [{ item: "openai", variable: null }])
    const [second] = await resolveAdHocItems(api, [{ item: "openai", variable: "OTHER" }])
    expect(first).toMatchObject({ item: "openai", variable: "OPENAI_API_KEY", hosts: ["api.openai.com"] })
    expect(first?.standIn).toMatch(/^sk-proj-jvph[0-9A-Za-z]{24}$/)
    expect(second?.variable).toBe("OTHER")
    expect(second?.standIn).not.toBe(first?.standIn)
    const v6 = apiDescribing("local", () => itemDescription({ slug: "local", binding: { hosts: ["[::1]", "10.1.2.3"] } }))
    expect((await resolveAdHocItems(v6, [{ item: "local", variable: "K" }]))[0]?.hosts).toEqual(["::1", "10.1.2.3"])
  })

  test("a query or Basic injection takes the prefix of the field it sends; an unknown prefix gives a bare stand-in", async () => {
    const query = apiDescribing("q", () => itemDescription({ slug: "q", injection: { in: "query", name: "api_key", field: "token" }, secretFields: [{ name: "token", prefix: "ghp_" }] }))
    expect((await resolveAdHocItems(query, [{ item: "q", variable: "Q" }]))[0]?.standIn).toMatch(/^ghp_jvph/)
    const basic = apiDescribing("b", () => itemDescription({ slug: "b", provider: null, injection: { in: "basic", username: "user", password: "pass" }, secretFields: [{ name: "pass", prefix: "" }] }))
    expect((await resolveAdHocItems(basic, [{ item: "b", variable: "B" }]))[0]?.standIn).toMatch(/^jvph[0-9A-Za-z]{24}$/)
  })

  test("a lease-only credential is refused, pointing at a project", async () => {
    const error = await refusal(resolveAdHocItems(apiDescribing("db", () => itemDescription({ slug: "db", binding: { hosts: [LEASE_ONLY_HOST] }, injection: null })), [{ item: "db", variable: "DATABASE_URL" }]))
    expect(error).toBeInstanceOf(CommandError)
    expect((error as CommandError).code).toBe(EXIT.refused)
    expect(error.message).toBe("--item db: it is a lease-only credential, which is delivered as its real value and only to a project's variable")
    expect((error as CommandError).next).toEqual({ say: "Use it through a project instead: mehen init, then mehen env set <NAME> --env <env> --item db, then mehen run.", command: "mehen init" })
  })

  test("a credential the vault will not show this machine (private without the scope, or not its own) is refused with what to check", async () => {
    const api = apiDescribing("mine", () => {
      throw new VaultApiError(404, { error: "not_found", message: 'No credential called "mine".' })
    })
    const error = await refusal(resolveAdHocItems(api, [{ item: "mine", variable: "K" }]))
    expect(error.message).toBe("--item mine: the vault does not let this machine use mine outside a project")
    expect((error as CommandError).code).toBe(EXIT.error)
    expect((error as CommandError).next?.say).toContain("A private credential needs a machine allowed your private credentials. A credential behind a protected environment is used only in an approved run of its project")
  })

  test("no template variable and no =VAR is a usage error naming the fix", async () => {
    const error = await refusal(resolveAdHocItems(apiDescribing("custom", () => itemDescription({ slug: "custom", provider: null })), [{ item: "custom", variable: null }]))
    expect(error).toBeInstanceOf(CliError)
    expect(error.message).toBe("--item custom: its template names no variable, so mehen cannot tell what to call it. Name it with --item custom=<VAR>.")
  })

  test("a host the CA cannot hold exactly, no host, a header map, no injection, or a disabled item is refused", async () => {
    const cases: [Record<string, unknown>, string][] = [
      [{ binding: { hosts: ["*.com"] } }, 'its host "*.com" cannot be held to exactly that host'],
      [{ binding: { hosts: [] } }, "it is bound to no host"],
      [{ injection: { in: "headers", field: "map" } }, "it is not sent as one key"],
      [{ injection: null }, "it is not sent as one key"],
      [{ status: "disabled" }, "it is disabled"],
    ]
    for (const [overrides, why] of cases) {
      const error = await refusal(resolveAdHocItems(apiDescribing("openai", () => itemDescription(overrides)), [{ item: "openai", variable: null }]))
      expect(error.message, why).toContain(why)
      expect((error as CommandError).next?.say, why).toBeTruthy()
    }
  })

  test("a vault whose description lacks what an ad hoc run needs, or that has no such route, is named as outdated", async () => {
    const { injection: _injection, ...noInjection } = itemDescription()
    const lacking = await refusal(resolveAdHocItems(apiDescribing("openai", () => noInjection), [{ item: "openai", variable: null }]))
    expect(lacking.message).toBe("--item openai: this vault cannot serve an ad hoc run: its description of openai lacks injection")
    expect((lacking as CommandError).next?.say).toStartWith("Update the vault, or use openai through a project")
    const old = await refusal(resolveAdHocItems(apiDescribing("openai", () => {
      throw new VaultApiError(405, { error: "bad_request", message: "Method not allowed." })
    }), [{ item: "openai", variable: null }]))
    expect(old.message).toBe("--item openai: this vault cannot serve an ad hoc run: it does not describe credentials")
  })
})
