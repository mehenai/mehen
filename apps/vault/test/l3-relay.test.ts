import { afterEach, describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { type ApprovalSubject, ITEM_HEADER, type RelayRequestInput, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { LEASE_ONLY_HOST, base64UrlEncode, leaseOnlyBinding, newPlaceholder, utf8 } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { type RelayMaterial, forwardRelay } from "../src/relay/forward.ts"
import { setRelayServices } from "../src/relay/services.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { authoriseRelay, decodedRequestBody } from "../src/vault/areas/relay.ts"
import { items } from "../src/vault/areas/items.ts"
import type { AuditRow } from "../src/vault/audit.ts"
import type { DevicePrincipal, VaultContext } from "../src/vault/core.ts"
import type { ApprovalPresentation, NewItem } from "../src/vault/services.ts"
import { fetchWorker, freshTenant, testDevice as fabricatedDevice } from "./helpers.ts"

import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"
const testDevice = (overrides: Partial<DevicePrincipal> = {}) => fabricatedDevice({ device: POLICY_DEVICE, ...overrides })

const SYSTEM = { kind: "system", reason: "test" } as const
const KEY = "sk-proj-0123456789abcdefghij"

function apiKeyItem(overrides: Partial<NewItem> = {}): NewItem {
  return {
    slug: "openai-personal",
    kind: "api-key",
    provider: "openai",
    account: "alex@example.com",
    accountVerified: false,
    tags: ["personal"],
    ceiling: "placeholder",
    binding: { hosts: ["api.openai.com"] },
    policy: { default: "allow", rules: [{ action: "deny", paths: ["/v1/organization/**"], note: "admin API" }] },
    injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
    publicFields: {},
    secretFields: { key: KEY },
    description: null,
    ...overrides,
  }
}

function request(overrides: Partial<RelayRequestInput> = {}): RelayRequestInput {
  return { item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models", headers: [], ...overrides }
}

function authorise(ctx: VaultContext, input: unknown, principal: DevicePrincipal = testDevice()): Promise<RelayMaterial> {
  return authoriseRelay(ctx, principal, input) as Promise<RelayMaterial>
}

async function inVault(fn: (ctx: VaultContext, sql: SqlStorage) => Promise<void>): Promise<void> {
  const stub = env.TENANT_VAULT.getByName(freshTenant())
  await runInDurableObject(stub, async (instance, state) => { await registerPolicyDevice(instance.context, testDevice()); await fn(instance.context, state.storage.sql) })
}

function audits(sql: SqlStorage, action: string): AuditRow[] {
  return sql.exec<AuditRow>("SELECT * FROM audit WHERE action = ? ORDER BY seq", action).toArray()
}

function header(material: RelayMaterial, name: string): string | undefined {
  return material.headers.find(([n]) => n.toLowerCase() === name.toLowerCase())?.[1]
}

afterEach(() => {
  setUpstreamFetch(null)
  setRelayServices({})
})

describe("relay.authorise, item mode", () => {
  it("injects the item on its own surface, strips hop-by-hop and cookie headers, and audits", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const material = await authorise(
        ctx,
        request({
          headers: [
            ["Authorization", "Bearer agent-chosen"],
            ["Cookie", "a=b"],
            ["Connection", "x-drop-me"],
            ["X-Drop-Me", "1"],
            ["Accept", "application/json"],
            ["Mehen-Proof", "nope"],
          ],
        }),
      )
      expect(header(material, "authorization")).toBe(`Bearer ${KEY}`)
      expect(header(material, "cookie")).toBeUndefined()
      expect(header(material, "x-drop-me")).toBeUndefined()
      expect(header(material, "mehen-proof")).toBeUndefined()
      expect(header(material, "accept")).toBe("application/json")
      expect(material.url).toBe("https://api.openai.com/v1/models")
      expect(material.label).toBe("openai-personal (alex@example.com)")
      expect(material.scrub).toContainEqual({ label: "openai-personal", value: KEY })
      const allowed = audits(sql, "relay.allow")
      expect(allowed).toHaveLength(1)
      expect(allowed[0]?.detail).not.toContain(KEY)
    })
  })

  it("injects query and basic surfaces as the item says", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem({ slug: "maps", injection: { in: "query", name: "auth", field: "key" }, binding: { hosts: ["maps.example.com"] } }), SYSTEM)
      const q = await authorise(ctx, request({ item: "maps", url: "https://maps.example.com/geo?auth=agent&x=1" }))
      expect(new URL(q.url).searchParams.get("auth")).toBe(KEY)
      expect(new URL(q.url).searchParams.get("x")).toBe("1")
      await items.putItem(
        ctx,
        {
          ...apiKeyItem({ slug: "basic-api", kind: "basic-auth", binding: { hosts: ["basic.example.com"] } }),
          injection: { in: "basic", username: "username", password: "password" },
          publicFields: { username: "alex" },
          secretFields: { password: "pa:ss-word-123" },
          ceiling: "relay",
        },
        SYSTEM,
      )
      const b = await authorise(ctx, request({ item: "basic-api", url: "https://basic.example.com/" }))
      expect(header(b, "authorization")).toBe(`Basic ${btoa("alex:pa:ss-word-123")}`)
      expect(b.scrub.map((s) => s.value)).toEqual(expect.arrayContaining(["pa:ss-word-123", btoa("alex:pa:ss-word-123")]))
    })
  })

  it("scrubs a query-injected secret echoed in the spelling the query string carried it", async () => {
    await inVault(async (ctx) => {
      const secret = "Summer 2024!(x)~'*"
      await items.putItem(ctx, apiKeyItem({ slug: "query-echo", ceiling: "relay", injection: { in: "query", name: "key", field: "key" }, binding: { hosts: ["api.example.com"] }, secretFields: { key: secret } }), SYSTEM)
      const material = await authorise(ctx, request({ item: "query-echo", url: "https://api.example.com/v1/things" }))
      const wire = new URL(material.url).search.slice("?key=".length)
      expect(wire).not.toBe(encodeURIComponent(secret))
      for (const status of [200, 302]) {
        setUpstreamFetch(async (req) => new Response(status === 200 ? `you asked for ${req.url}` : null, { status, headers: { location: req.url } }))
        const echoed: string[][] = []
        const res = await forwardRelay(material, null, { onEcho: (found) => echoed.push(found) })
        const text = await res.text()
        expect(res.headers.get("location")).toBe("https://api.example.com/v1/things?key=[redacted:query-echo]")
        if (status === 200) expect(text).toBe("you asked for https://api.example.com/v1/things?key=[redacted:query-echo]")
        expect(echoed).toEqual([["query-echo"]])
      }
    })
  })

  it("scrubs a secret an upstream echoes in the body percent-encoded as PHP's rawurlencode writes it", async () => {
    await inVault(async (ctx) => {
      const secret = "Summer 2024!(x)~'*"
      await items.putItem(ctx, apiKeyItem({ slug: "body-echo", ceiling: "relay", binding: { hosts: ["api.example.com"] }, secretFields: { key: secret } }), SYSTEM)
      const material = await authorise(ctx, request({ item: "body-echo", url: "https://api.example.com/v1/things" }))
      const rawurlencoded = "Summer%202024%21%28x%29~%27%2A"
      expect([encodeURIComponent(secret), new URLSearchParams([["", secret]]).toString().slice(1)]).not.toContain(rawurlencoded)
      setUpstreamFetch(async () => new Response(`{"error":"unknown key ${rawurlencoded}"}`, { status: 401, headers: { "content-type": "application/json" } }))
      const echoed: string[][] = []
      const res = await forwardRelay(material, null, { onEcho: (found) => echoed.push(found) })
      expect(await res.text()).toBe('{"error":"unknown key [redacted:body-echo]"}')
      expect(echoed).toEqual([["body-echo"]])
    })
  })

  it("refuses an unbound host, scheme and port", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      for (const url of ["https://evil.example.com/v1/models", "https://api.openai.com.evil.example/v1", "http://api.openai.com/v1/models", "https://api.openai.com:8443/v1/models"]) {
        await expect(authorise(ctx, request({ url }))).rejects.toMatchObject({ code: "binding_refused" })
      }
      expect(audits(sql, "relay.refuse").length).toBe(4)
      expect(audits(sql, "relay.allow")).toHaveLength(0)
    })
  })

  it("refuses every path traversal form before anything is decrypted", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem({ binding: { hosts: ["api.openai.com"], paths: ["/v1/**"] } }), SYSTEM)
      for (const url of [
        "https://api.openai.com/v1/../admin",
        "https://api.openai.com/v1/%2e%2e/admin",
        "https://api.openai.com/v1/%2E%2e/admin",
        "https://api.openai.com/v1/.%2e/admin",
        "https://api.openai.com/v1%2fadmin",
        "https://api.openai.com/v1%5cadmin",
        "https://api.openai.com/v1\\..\\admin",
        "https://api.openai.com/v1//models",
        "https://api.openai.com/v1/./models",
        "https://api.openai.com/v1/%00",
      ]) {
        await expect(authorise(ctx, request({ url })), url).rejects.toMatchObject({ code: "binding_refused" })
      }
      await expect(authorise(ctx, request({ url: "https://api.openai.com/admin" }))).rejects.toMatchObject({ code: "binding_refused" })
      await expect(authorise(ctx, request({ url: "https://user:pw@api.openai.com/v1/models" }))).rejects.toMatchObject({ code: "binding_refused" })
    })
  })

  it("never sends a lease-only item, even to its reserved host", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem({ slug: "jwt-secret", provider: null, ceiling: "lease", binding: leaseOnlyBinding() }), SYSTEM)
      for (const url of [`https://${LEASE_ONLY_HOST}/`, "https://api.openai.com/v1/models"]) {
        const refused = await authorise(ctx, request({ item: "jwt-secret", url })).catch((e: unknown) => e)
        expect(refused, url).toMatchObject({ code: "binding_refused", message: expect.stringContaining(". No host: only delivered into a process with mehen run.") })
        expect((refused as VaultError).message).not.toContain(`binding: ${LEASE_ONLY_HOST}`)
      }
      await items.putItem(ctx, apiKeyItem({ slug: "placeholder-ceiling", provider: null, ceiling: "placeholder", binding: leaseOnlyBinding() }), SYSTEM)
      expect(await authorise(ctx, request({ item: "placeholder-ceiling", url: "https://api.openai.com/v1/models" })).catch((e: unknown) => e)).toMatchObject({ code: "binding_refused", message: expect.stringContaining(". No host: stored only; a human can allow mehen run by setting its ceiling to lease.") })
      expect(audits(sql, "relay.allow")).toHaveLength(0)
    })
  })

  it("refuses method-override headers and parameters", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      // CGI and FastCGI read "_" in a header name as "-".
      for (const name of ["X-HTTP-Method-Override", "x-http-method", "X-Method-Override", "X_HTTP_Method_Override", "x-http_method"]) {
        await expect(authorise(ctx, request({ method: "POST", headers: [[name, "DELETE"]] }))).rejects.toMatchObject({ code: "forbidden" })
      }
      await expect(authorise(ctx, request({ url: "https://api.openai.com/v1/models?_method=DELETE" }))).rejects.toMatchObject({ code: "forbidden" })
      // PHP drops leading spaces and reads "." and " " as "_" in a field name.
      for (const name of [".method", "%2Emethod", "+_method"]) {
        await expect(authorise(ctx, request({ url: `https://api.openai.com/v1/models?${name}=DELETE` })), name).rejects.toMatchObject({ code: "forbidden" })
        await expect(authorise(ctx, request({ method: "POST", headers: [["Content-Type", "application/x-www-form-urlencoded"]], body: base64UrlEncode(utf8(`${name}=DELETE`)) })), name).rejects.toMatchObject({ code: "forbidden" })
      }
      await expect(authorise(ctx, request({ method: "TRACE" }))).rejects.toMatchObject({ code: "bad_request" })
    })
  })

  it("refuses method-override fields in a form, multipart or top-level JSON body, naming the field without echoing the body", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const post = (body: string, contentType: string | null | string[]) =>
        authorise(ctx, request({ method: "POST", headers: contentType === null ? [] : [contentType].flat().map((value): [string, string] => ["Content-Type", value]), body: base64UrlEncode(utf8(body)) }))
      const boundary = "b0undary"
      const multipart = (disposition: string, value: string) =>
        [`--${boundary}`, `Content-Disposition: form-data; ${disposition}`, "", value, `--${boundary}`, 'Content-Disposition: form-data; name="note"', "", "body-marker-7f3a", `--${boundary}--`, ""].join("\r\n")
      const refused: [string, string | null, string][] = [
        ["note=body-marker-7f3a&_method=DELETE", "application/x-www-form-urlencoded", "_method"],
        ["note=body-marker-7f3a&_MeThOd=DELETE", "application/x-www-form-urlencoded; charset=utf-8", "_method"],
        ["note=body-marker-7f3a&_method=DELETE", null, "_method"],
        [multipart('name="_httpmethod"', "DELETE"), `multipart/form-data; boundary=${boundary}`, "_httpmethod"],
        [JSON.stringify({ note: "body-marker-7f3a", _method: "DELETE" }), "application/json", "_method"],
        [JSON.stringify({ note: "body-marker-7f3a", "X-HTTP-Method-Override": "DELETE" }), "application/merge-patch+json", "x-http-method-override"],
        ["note=body-marker-7f3a&_method=DELETE", "application/x-www-form-urlencoded, text/plain", "_method"],
        [JSON.stringify({ note: "body-marker-7f3a", _method: "DELETE" }), "text/plain; x=/json", "_method"],
        [multipart('name="note"; name="_method"', "DELETE"), `multipart/form-data; boundary=${boundary}`, "_method"],
        [multipart('name="_method"; x="; filename=a"', "DELETE"), `multipart/form-data; boundary=${boundary}`, "_method"],
        [multipart('name="_method"', "DELETE"), `multipart/form-data; boundary=other; boundary=${boundary}`, "_method"],
        [multipart('name="_method"', "DELETE"), `multipart/mixed; boundary=${boundary}`, "_method"],
        [multipart('name="_method"', "DELETE"), `multipart/related; boundary=${boundary}`, "_method"],
        // A file named after the field is refused too: the body is not parsed.
        [multipart('name="_method"; filename="m.txt"', "_method=DELETE"), `multipart/form-data; boundary=${boundary}`, "_method"],
      ]
      for (const [body, contentType, field] of refused) {
        const error = await post(body, contentType).catch((e: unknown) => e)
        expect(error, `${contentType}: ${body}`).toMatchObject({ code: "forbidden", message: expect.stringContaining(field) })
        expect((error as VaultError).message).not.toContain("body-marker-7f3a")
      }
      const twoTypes = await post("note=body-marker-7f3a&_method=DELETE", ["application/x-www-form-urlencoded", "text/plain"]).catch((e: unknown) => e)
      expect(twoTypes).toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
      expect(audits(sql, "relay.allow")).toHaveLength(0)
      const allowed: [string, string | null][] = [
        ["note=body-marker-7f3a&method=DELETE", "application/x-www-form-urlencoded"],
        [multipart('name="upload"; filename="m.txt"', "method=DELETE"), `multipart/form-data; boundary=${boundary}`],
        [JSON.stringify({ data: { _method: "DELETE" } }), "application/json"],
        [JSON.stringify([{ _method: "DELETE" }]), "application/json"],
        ['{"_method": "DELETE",', "application/json"],
      ]
      for (const [body, contentType] of allowed) await expect(post(body, contentType), body).resolves.toMatchObject({ method: "POST" })
    })
  })

  it("decompresses a gzip or deflate body for a method-override field within a cap, and refuses one it cannot read", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const compressed = async (data: string | Uint8Array<ArrayBuffer>, format: "gzip" | "deflate") => new Uint8Array(await new Response((new Response(data).body as ReadableStream).pipeThrough(new CompressionStream(format))).arrayBuffer())
      const post = (body: Uint8Array<ArrayBuffer>, contentType: string, contentEncoding: string) => authorise(ctx, request({ method: "POST", headers: [["Content-Type", contentType], ["Content-Encoding", contentEncoding]], body: base64UrlEncode(body) }))
      const form = "note=body-marker-7f3a&_method=DELETE"
      const json = JSON.stringify({ note: "body-marker-7f3a", _method: "DELETE" })
      const refused: [Uint8Array<ArrayBuffer>, string, string][] = [
        [await compressed(form, "gzip"), "application/x-www-form-urlencoded", "gzip"],
        [await compressed(form, "gzip"), "application/x-www-form-urlencoded", "X-GZIP"],
        [await compressed(json, "deflate"), "application/json", "deflate"],
        [await compressed(await compressed(json, "deflate"), "gzip"), "application/json", "deflate, gzip"],
        [await compressed(form, "gzip"), "application/x-www-form-urlencoded", "identity, gzip"],
      ]
      for (const [body, contentType, contentEncoding] of refused) {
        const error = await post(body, contentType, contentEncoding).catch((e: unknown) => e)
        expect(error, contentEncoding).toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
        expect((error as VaultError).message).not.toContain("body-marker-7f3a")
      }
      const unread: [Uint8Array<ArrayBuffer>, string][] = [
        [utf8(form), "br"],
        [utf8(form), "zstd"],
        [utf8(form), "gzip"],
        [await compressed(form, "gzip"), "deflate"],
        [new Uint8Array([...await compressed("note=x", "gzip"), ...utf8("note=y")]), "gzip"],
        [new Uint8Array([...await compressed("note=x", "gzip"), 0, 0, 0, 0]), "gzip"],
        [new Uint8Array([...await compressed("note=body-marker-7f3a&", "gzip"), ...await compressed("_method=DELETE", "gzip")]), "gzip"],
        [new Uint8Array([...await compressed('{"_method":"DELETE"}', "gzip"), ...await compressed("x", "gzip")]), "gzip"],
        [new Uint8Array([...await compressed("note=x", "deflate"), ...utf8("note=y")]), "deflate"],
        [(await compressed(form, "gzip")).slice(0, -4), "gzip"],
        [(await compressed(form, "deflate")).slice(0, -2), "deflate"],
      ]
      for (const [body, contentEncoding] of unread) {
        const error = await post(body, "application/x-www-form-urlencoded", contentEncoding).catch((e: unknown) => e)
        expect(error, contentEncoding).toMatchObject({ code: "forbidden", message: expect.stringContaining(contentEncoding) })
        expect((error as VaultError).extra.next?.say, contentEncoding).toContain("uncompressed")
      }
      // The cap is the largest body as sent, 14,000,000 base64url characters.
      const bomb = await compressed(`note=${"0".repeat(10_500_000)}&_method=DELETE`, "gzip")
      expect(bomb.length).toBeLessThan(64 * 1024)
      const tooLarge = await post(bomb, "application/x-www-form-urlencoded", "gzip").catch((e: unknown) => e)
      expect(tooLarge).toMatchObject({ code: "too_large", message: expect.stringContaining("10500000") })
      expect(audits(sql, "relay.allow")).toHaveLength(0)
      await expect(post(await compressed(JSON.stringify({ note: "x", method: "DELETE" }), "gzip"), "application/json", "gzip")).resolves.toMatchObject({ method: "POST" })
      await expect(post(utf8(JSON.stringify({ note: "x" })), "application/json", "identity")).resolves.toMatchObject({ method: "POST" })
    })
  })

  it("refuses a gzip form override on a POST the base policy allows over a DELETE deny, before anything is forwarded", async () => {
    await inVault(async (ctx, sql) => {
      const policy = { default: "approve" as const, rules: [{ action: "allow" as const, methods: ["POST"], paths: ["/notes"] }, { action: "deny" as const, methods: ["DELETE"], paths: ["/notes"] }] }
      await items.putItem(ctx, apiKeyItem({ slug: "notes", provider: null, binding: { hosts: ["api.example.com"] }, policy }), SYSTEM)
      const forwarded: string[] = []
      setUpstreamFetch(async (req) => {
        forwarded.push(`${req.method} ${req.headers.get("content-encoding")}`)
        return new Response(null, { status: 204 })
      })
      const gzip = async (data: string) => new Uint8Array(await new Response((new Response(data).body as ReadableStream).pipeThrough(new CompressionStream("gzip"))).arrayBuffer())
      const relay = async (method: string, body: Uint8Array<ArrayBuffer> | null, contentEncoding: string | null, contentType = "application/x-www-form-urlencoded") => {
        const headers: [string, string][] = [["Content-Type", contentType], ...(contentEncoding === null ? [] : [["Content-Encoding", contentEncoding] as [string, string]])]
        const material = await authorise(ctx, request({ item: "notes", method, url: "https://api.example.com/notes", headers, ...(body === null ? {} : { body: base64UrlEncode(body) }) }))
        return forwardRelay(material, body)
      }
      await expect(relay("DELETE", null, null)).rejects.toMatchObject({ code: "policy_denied" })
      await expect(relay("POST", utf8("note=x&_method=DELETE"), null)).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
      await expect(relay("POST", await gzip("note=x&_method=DELETE"), "gzip")).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
      const multipart = ["--b0undary", 'Content-Disposition: form-data; name="_method"', "", "DELETE", "--b0undary--", ""].join("\r\n")
      await expect(relay("POST", await gzip(multipart), "gzip", "multipart/form-data; boundary=b0undary")).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
      await expect(relay("POST", await gzip(JSON.stringify({ note: "x", _method: "DELETE" })), "gzip", "application/json")).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
      expect(forwarded).toEqual([])
      expect(audits(sql, "relay.allow")).toHaveLength(0)
      await expect(relay("POST", await gzip("note=x"), "gzip")).resolves.toMatchObject({ status: 204 })
      expect(forwarded).toEqual(["POST gzip"])
    })
  })

  it("refuses a body in more than three stacked codings, names an unknown coding quoted and short, and refuses a Content_Encoding header", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const compressed = async (data: string | Uint8Array<ArrayBuffer>, format: "gzip" | "deflate") => new Uint8Array(await new Response((new Response(data).body as ReadableStream).pipeThrough(new CompressionStream(format))).arrayBuffer())
      const post = (body: Uint8Array<ArrayBuffer>, headers: [string, string][]) => authorise(ctx, request({ method: "POST", headers: [["Content-Type", "application/json"], ...headers], body: base64UrlEncode(body) }))
      let body = utf8(JSON.stringify({ note: "x" }))
      for (let i = 0; i < 4; i++) body = await compressed(body, "gzip")
      const stacked = await post(body, [["Content-Encoding", "gzip, gzip, gzip, gzip"]]).catch((e: unknown) => e)
      expect(stacked).toMatchObject({ code: "forbidden", message: expect.stringContaining("more than 3") })
      const long = `x${"y".repeat(99)}`
      const unknown = await post(utf8("{}"), [["Content-Encoding", long]]).catch((e: unknown) => e)
      expect(unknown).toMatchObject({ code: "forbidden", message: expect.stringContaining(JSON.stringify(long.slice(0, 40))) })
      expect((unknown as VaultError).message).not.toContain(long.slice(0, 41))
      await expect(post(utf8("{}"), [["Content-Encoding", 'b"r']])).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining('"b\\"r"') })
      for (const name of ["Content_Encoding", "content_encoding"]) {
        const refused = await post(await compressed(JSON.stringify({ _method: "DELETE" }), "gzip"), [[name, "gzip"]]).catch((e: unknown) => e)
        expect(refused, name).toMatchObject({ code: "forbidden", message: expect.stringContaining(name) })
      }
      expect(audits(sql, "relay.allow")).toHaveLength(0)
      const three = await compressed(await compressed(await compressed(JSON.stringify({ note: "x" }), "gzip"), "deflate"), "gzip")
      await expect(post(three, [["Content-Encoding", "gzip, deflate, gzip"]])).resolves.toMatchObject({ method: "POST" })
    })
  })

  it("stops decoding a body at the cap, however far it would inflate", async () => {
    const stream = new CompressionStream("gzip")
    const compressed = new Response(stream.readable).arrayBuffer()
    const writer = stream.writable.getWriter()
    const zeros = new Uint8Array(1024 * 1024)
    for (let i = 0; i < 64; i++) await writer.write(zeros)
    await writer.close()
    const bomb = new Uint8Array(await compressed)
    expect(bomb.length).toBeLessThan(128 * 1024)
    expect(decodedRequestBody(bomb, "gzip", 1024 * 1024)).toEqual({ tooLarge: true })
  })

  it("reads the raw body and every decoding step's output for a method-override field, as an upstream may undo none or some of the codings", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const compressed = async (data: string | Uint8Array<ArrayBuffer>, format: "gzip" | "deflate") => new Uint8Array(await new Response((new Response(data).body as ReadableStream).pipeThrough(new CompressionStream(format))).arrayBuffer())
      const post = (body: Uint8Array<ArrayBuffer>, contentEncoding: string) => authorise(ctx, request({ method: "POST", headers: [["Content-Type", "application/x-www-form-urlencoded"], ["Content-Encoding", contentEncoding]], body: base64UrlEncode(body) }))
      // A gzip member whose header carries the field in its comment (FLG
      // FCOMMENT, 0x10), which the CRC does not cover and a decoder skips.
      const plain = await compressed("note=x", "gzip")
      const comment = utf8("&_method=DELETE&\0")
      const commented = new Uint8Array(plain.length + comment.length)
      commented.set(plain.subarray(0, 10))
      commented[3] = (plain[3] ?? 0) | 0x10
      commented.set(comment, 10)
      commented.set(plain.subarray(10), 10 + comment.length)
      const refused: [Uint8Array<ArrayBuffer>, string][] = [
        [commented, "gzip"],
        [await compressed(commented, "deflate"), "gzip, deflate"],
      ]
      for (const [body, contentEncoding] of refused) {
        await expect(post(body, contentEncoding), contentEncoding).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
      }
      expect(audits(sql, "relay.allow")).toHaveLength(0)
      await expect(post(plain, "gzip")).resolves.toMatchObject({ method: "POST" })
      await expect(post(await compressed(plain, "deflate"), "gzip, deflate")).resolves.toMatchObject({ method: "POST" })
    })
  })

  it("reads a UTF-16 body for a method-override field in either byte order, and refuses a UTF-32 or UTF-7 one", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const utf16 = (text: string, order: "le" | "be") => new Uint8Array([...text].flatMap((c) => (order === "le" ? [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8] : [c.charCodeAt(0) >> 8, c.charCodeAt(0) & 0xff])))
      const post = (body: Uint8Array<ArrayBuffer>, contentType: string) => authorise(ctx, request({ method: "POST", headers: [["Content-Type", contentType]], body: base64UrlEncode(body) }))
      for (const order of ["le", "be"] as const) {
        const body = utf16(JSON.stringify({ note: "body-marker-7f3a", _method: "DELETE" }), order)
        await expect(post(body, `application/json; charset=utf-16${order}`), order).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
        await expect(post(new Uint8Array([...(order === "le" ? [0xff, 0xfe] : [0xfe, 0xff]), ...body]), "application/json"), order).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("_method") })
        await expect(post(utf16(JSON.stringify({ note: "x" }), order), `application/json; charset=utf-16${order}`), order).resolves.toMatchObject({ method: "POST" })
      }
      const utf32 = await post(utf8('{"note":"x"}'), "application/json; charset=utf-32").catch((e: unknown) => e)
      expect(utf32).toMatchObject({ code: "forbidden", message: expect.stringContaining("UTF-8") })
      await expect(post(utf8('{"+AF8-method":"DELETE"}'), "application/json; charset=utf-7")).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("UTF-8") })
      expect(audits(sql, "relay.allow")).toHaveLength(2)
    })
  })

  it("refuses a form declared in a charset it does not read, such as x-utf-16le, before anything is allowed", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const utf16le = (text: string) => new Uint8Array([...text].flatMap((c) => [c.charCodeAt(0) & 0xff, c.charCodeAt(0) >> 8]))
      const post = (body: Uint8Array<ArrayBuffer>, contentType: string) => authorise(ctx, request({ method: "POST", headers: [["Content-Type", contentType]], body: base64UrlEncode(body) }))
      await expect(post(utf16le("note=body-marker-7f3a&_method=DELETE"), "application/x-www-form-urlencoded; charset=x-utf-16le")).rejects.toMatchObject({ code: "forbidden", message: expect.stringContaining("UTF-8") })
      expect(audits(sql, "relay.allow")).toHaveLength(0)
      await expect(post(utf8("note=body-marker-7f3a"), "application/x-www-form-urlencoded; charset=iso-8859-1")).resolves.toMatchObject({ method: "POST" })
    })
  })

  it("meets the rules with a path cut at an encoded ? or #, and forwards paths no rule covers as sent", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      for (const path of ["/v1/organization%3Fx", "/v1/organization%23x"]) {
        await expect(authorise(ctx, request({ url: `https://api.openai.com${path}` })), path).rejects.toMatchObject({ code: "policy_denied" })
      }
      await expect(authorise(ctx, request({ url: "https://api.openai.com/v1/files/user%231" }))).resolves.toMatchObject({ url: "https://api.openai.com/v1/files/user%231" })
      const policy = { default: "deny" as const, rules: [{ action: "allow" as const, methods: ["POST"], paths: ["/v1/*/send"] }, { action: "allow" as const, methods: ["GET"], paths: ["/repos/*/*/git/refs/**"] }] }
      await items.putItem(ctx, apiKeyItem({ slug: "refs", binding: { hosts: ["api.example.com"] }, policy }), SYSTEM)
      const refs = (method: string, path: string) => authorise(ctx, request({ item: "refs", method, url: `https://api.example.com${path}` }))
      await expect(refs("GET", "/repos/o/r/git/refs/heads/fix%23123")).resolves.toMatchObject({ url: "https://api.example.com/repos/o/r/git/refs/heads/fix%23123" })
      await expect(refs("POST", "/v1/x/send")).resolves.toMatchObject({ method: "POST" })
      await expect(refs("POST", "/v1/delete%3F/send")).rejects.toMatchObject({ code: "policy_denied" })
    })
  })

  it("names the encoded ? or # when a path is outside the binding only once cut there", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem({ slug: "gitlab", binding: { hosts: ["gitlab.example"], paths: ["/api/v4/projects/*/repository/files/*/raw"] } }), SYSTEM)
      const get = (path: string) => authorise(ctx, request({ item: "gitlab", url: `https://gitlab.example${path}` }))
      await expect(get("/api/v4/projects/1/repository/files/what%3F.md/raw")).rejects.toMatchObject({
        code: "binding_refused",
        message: expect.stringContaining("the path, read up to its encoded ? (%3F) as an upstream that decodes it again may end it, is outside its binding"),
      })
      await expect(get("/api/v4/projects/1/issues")).rejects.toMatchObject({ code: "binding_refused", message: expect.stringContaining("(the path is outside its binding") })
    })
  })

  it("refuses URL-rewrite headers, which an upstream may route on instead of the checked path", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      await expect(authorise(ctx, request({ url: "https://api.openai.com/v1/organization/keys" }))).rejects.toMatchObject({ code: "policy_denied" })
      for (const name of ["X-Original-URL", "x-rewrite-url", "X_Original_URL", "x_rewrite-url"]) {
        const refused = await authorise(ctx, request({ headers: [[name, "/v1/organization/keys"]] })).catch((e: unknown) => e)
        expect(refused, name).toMatchObject({ code: "forbidden", message: expect.stringContaining(name) })
      }
      expect(audits(sql, "relay.allow")).toHaveLength(0)
    })
  })

  it("refuses path and host routing headers, and forwards the client address and scheme ones as sent", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const routing: [string, string, string][] = [
        ["X-Forwarded-Prefix", "/v1/organization", "path"],
        ["x-forwarded-path", "/v1/organization/keys", "path"],
        ["X-Forwarded-Uri", "/v1/organization/keys", "path"],
        ["X-Forwarded-URL", "https://api.openai.com/v1/organization/keys", "path"],
        ["X-Original-URI", "/v1/organization/keys", "path"],
        ["X_Forwarded_Prefix", "/v1/organization", "path"],
        ["X-Forwarded-Host", "admin.openai.com", "host"],
        ["x_forwarded_server", "admin.openai.com", "host"],
        ["Forwarded", "for=192.0.2.1;host=admin.openai.com", "host"],
        ["X-Original-Host", "admin.openai.com", "host"],
        ["x_original_host", "admin.openai.com", "host"],
      ]
      for (const [name, value, names] of routing) {
        const refused = await authorise(ctx, request({ headers: [[name, value]] })).catch((e: unknown) => e)
        expect(refused, name).toMatchObject({ code: "forbidden", message: expect.stringContaining(name) })
        expect((refused as VaultError).message, name).toContain(`the ${names} they name`)
        expect((refused as VaultError).extra.next?.say, name).toContain(`send the real ${names}`)
      }
      expect(audits(sql, "relay.allow")).toHaveLength(0)
      const kept: [string, string][] = [
        ["X-Forwarded-For", "192.0.2.1"],
        ["X-Forwarded-Proto", "https"],
        ["X-Forwarded-Port", "443"],
        ["X-Real-IP", "192.0.2.1"],
      ]
      const material = await authorise(ctx, request({ headers: kept }))
      for (const [name, value] of kept) expect(header(material, name), name).toBe(value)
    })
  })

  it("refuses IP literals, our own origin and workers.dev unless bound exactly", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem({ slug: "wild-ip", binding: { hosts: ["*.0.0.1"] } }), SYSTEM)
      await expect(authorise(ctx, request({ item: "wild-ip", url: "https://127.0.0.1/x" }))).rejects.toMatchObject({ code: "binding_refused" })
      await items.putItem(ctx, apiKeyItem({ slug: "exact-ip", binding: { hosts: ["127.0.0.1"] } }), SYSTEM)
      await expect(authorise(ctx, request({ item: "exact-ip", url: "https://127.0.0.1/x" }))).resolves.toMatchObject({ url: "https://127.0.0.1/x" })
      // The WHATWG parser canonicalises other IPv4 spellings first.
      await expect(authorise(ctx, request({ item: "wild-ip", url: "https://0x7f.0.0.1/x" }))).rejects.toMatchObject({ code: "binding_refused" })
      await items.putItem(ctx, apiKeyItem({ slug: "wild-own", binding: { hosts: ["*.test"] } }), SYSTEM)
      await expect(authorise(ctx, request({ item: "wild-own", url: "https://vault.test/v1/me" }))).rejects.toMatchObject({ code: "binding_refused" })
      await items.putItem(ctx, apiKeyItem({ slug: "wild-workers", binding: { hosts: ["*.workers.dev"] } }), SYSTEM)
      await expect(authorise(ctx, request({ item: "wild-workers", url: "https://x.y.workers.dev/" }))).rejects.toMatchObject({ code: "binding_refused" })
      await items.putItem(ctx, apiKeyItem({ slug: "wild-v6", binding: { hosts: ["[::1]"] } }), SYSTEM)
      await expect(authorise(ctx, request({ item: "wild-v6", url: "https://[::1]/" }))).resolves.toMatchObject({ url: "https://[::1]/" })
      await expect(authorise(ctx, request({ item: "wild-ip", url: "https://[::2]/" }))).rejects.toMatchObject({ code: "binding_refused" })
    })
  })

  it("refuses by policy, by device scope and by item status", async () => {
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      await expect(authorise(ctx, request({ url: "https://api.openai.com/v1/organization/users" }))).rejects.toMatchObject({ code: "policy_denied" })
      expect(audits(sql, "relay.deny")).toHaveLength(1)
      await expect(authorise(ctx, request(), testDevice({ scope: { tags: ["work"], projects: [], maxEnvironment: "unprotected", modes: ["relay"] } }))).rejects.toMatchObject({ code: "forbidden" })
      await expect(authorise(ctx, request(), testDevice({ scope: { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["lease"] } }))).rejects.toMatchObject({ code: "forbidden" })
      items.setStatus(ctx, "openai-personal", "needs_reauth", "rotated elsewhere")
      const refused = await authorise(ctx, request()).catch((e: unknown) => e)
      expect(refused).toBeInstanceOf(VaultError)
      expect(refused).toMatchObject({ code: "needs_reauth", extra: { next: { url: "https://vault.test/items/openai-personal" } } })
      await expect(authorise(ctx, request({ item: "missing-item" }))).rejects.toMatchObject({ code: "not_found" })
      await expect(authorise(ctx, request({ run: "run_x" }))).rejects.toMatchObject({ code: "bad_request" })
      await expect(authorise(ctx, request({ method: "GET", body: base64UrlEncode(utf8("x")) }))).rejects.toMatchObject({ code: "bad_request" })
    })
  })

  it("presents a stable exact request subject and a decoded Gmail send without a grant store", async () => {
    const seen: { subject: ApprovalSubject; presentation: ApprovalPresentation }[] = []
    setRelayServices({
      reviewRequest: async (_ctx, _principal, subject, presentation) => {
        seen.push({ subject, presentation })
        if (seen.length === 1) throw new VaultError("approval_required", "Approve it.", { approval: "apr_1", next: { url: "https://vault.test/a/apr_1", say: "approve" } })

      },
    })
    await inVault(async (ctx) => {
      await items.putItem(
        ctx,
        {
          // The presentation keys off the provider; the OAuth path is covered in l3-oauth.
          ...apiKeyItem({ slug: "gmail-alex", provider: "google-gmail", binding: { hosts: ["gmail.googleapis.com"] } }),
          policy: { default: "allow", rules: [{ action: "approve", methods: ["POST"], paths: ["/gmail/v1/users/*/messages/send"] }] },
          secretFields: { key: "ya29.token-value" },
        },
        SYSTEM,
      )
      const message = [
        "To: Bob <bob@example.com>",
        "Cc: carol@example.com",
        "Bcc: dave@example.com",
        "Subject: =?UTF-8?B?UXVhcnRlcmx5IHJlcG9ydCDinJM=?=",
        "Content-Type: multipart/alternative; boundary=\"b1\"",
        "",
        "--b1",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: quoted-printable",
        "",
        "Hi Bob,=0A=0AThe numbers are attached.",
        "--b1",
        "Content-Type: text/html",
        "",
        "<p>Hi</p>",
        "--b1--",
      ].join("\r\n")
      const body = base64UrlEncode(utf8(JSON.stringify({ raw: base64UrlEncode(utf8(message)) })))
      const req = request({ item: "gmail-alex", method: "POST", url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", body })
      await expect(authorise(ctx, req)).rejects.toMatchObject({ code: "approval_required", extra: { approval: "apr_1" } })
      const material = await authorise(ctx, req)
      expect(seen).toHaveLength(2)
      expect(seen[0]?.subject).toEqual(seen[1]?.subject)
      expect(seen[0]?.subject).toMatchObject({ item: "gmail-alex", method: "POST", url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", constraints: { uses: 1, ttlSeconds: 600 } })
      const p = seen[0]?.presentation as ApprovalPresentation
      expect(p.title).toBe("Send an email")
      expect(p.email?.headers).toEqual(
        expect.arrayContaining([
          { name: "To", value: "Bob <bob@example.com>", highlight: true },
          { name: "Cc", value: "carol@example.com", highlight: true },
          { name: "Bcc", value: "dave@example.com", highlight: true },
          { name: "Subject", value: "Quarterly report \u2713", highlight: false },
        ]),
      )
      expect(p.email?.sections.map((s) => s.text)).toEqual(["Hi Bob,\n\nThe numbers are attached.", "Hi", "<p>Hi</p>"])
      expect(p.body).toBe(message)
      expect(header(material, "authorization")).toBe("Bearer ya29.token-value")
    })
  })
})

describe("relay.authorise, run mode", () => {
  const placeholder = newPlaceholder(KEY)
  const runOf = (hosts = ["api.openai.com"]) =>
    setRelayServices({ placeholdersFor: (_ctx, _principal, run) => (run === "run_1" ? [{ placeholder, item: "openai-personal", field: "key", hosts }] : []) })

  it("swaps a placeholder only on the item's declared surface", async () => {
    runOf()
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const material = await authorise(ctx, request({ item: undefined, run: "run_1", headers: [["Authorization", `Bearer ${placeholder}`]] }))
      expect(header(material, "authorization")).toBe(`Bearer ${KEY}`)
      expect(material.items).toEqual(["openai-personal"])
    })
  })

  it("refuses and records a tripwire for a placeholder in a body, a query, another header or at an unbound host", async () => {
    runOf()
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      const auth: [string, string] = ["Authorization", `Bearer ${placeholder}`]
      const cases: RelayRequestInput[] = [
        request({ item: undefined, run: "run_1", method: "POST", headers: [auth], body: base64UrlEncode(utf8(JSON.stringify({ comment: `leak ${placeholder}` }))) }),
        request({ item: undefined, run: "run_1", headers: [auth], url: `https://api.openai.com/v1/models?q=${placeholder}` }),
        request({ item: undefined, run: "run_1", headers: [auth, ["X-Note", placeholder]] }),
        request({ item: undefined, run: "run_1", headers: [auth], url: `https://api.openai.com/v1/${placeholder}` }),
        request({ item: undefined, run: "run_1", headers: [auth], url: "https://evil.example.com/v1/models" }),
        request({ item: undefined, run: "run_1", headers: [["Authorization", "Bearer sk-proj-jvph000000000000000000000000"]] }),
      ]
      for (const c of cases) await expect(authorise(ctx, c)).rejects.toMatchObject({ code: "surface_refused" })
      const trips = audits(sql, "relay.tripwire")
      expect(trips).toHaveLength(cases.length)
      expect(trips[0]?.detail).toContain("body")
      for (const t of trips) expect(t.detail).not.toContain(placeholder)
      expect(audits(sql, "relay.allow")).toHaveLength(0)
    })
  })

  it("never swaps a placeholder for a lease-only item, refusing it as at an unbound host", async () => {
    runOf([LEASE_ONLY_HOST])
    await inVault(async (ctx, sql) => {
      await items.putItem(ctx, apiKeyItem({ provider: null, ceiling: "lease", binding: leaseOnlyBinding() }), SYSTEM)
      await expect(authorise(ctx, request({ item: undefined, run: "run_1", url: `https://${LEASE_ONLY_HOST}/v1/models`, headers: [["Authorization", `Bearer ${placeholder}`]] }))).rejects.toMatchObject({ code: "surface_refused" })
      expect(audits(sql, "relay.tripwire")).toHaveLength(1)
      expect(audits(sql, "relay.allow")).toHaveLength(0)
    })
  })

  it("refuses a run request that carries no placeholder at all", async () => {
    runOf()
    await inVault(async (ctx) => {
      await items.putItem(ctx, apiKeyItem(), SYSTEM)
      await expect(authorise(ctx, request({ item: undefined, run: "run_1" }))).rejects.toMatchObject({ code: "bad_request" })
    })
  })
})

describe("relay upstream forwarding", () => {
  const secret = 'tok/en+with"quote&amp=0123456789abcdef'
  const material: RelayMaterial = {
    method: "GET",
    url: "https://api.example.com/echo",
    headers: [["authorization", `Bearer ${secret}`]],
    scrub: [{ label: "echo-item", value: secret }],
    label: "echo-item (alex@example.com)",
    items: ["echo-item"],
  }

  function chunked(text: string, size: number): ReadableStream<Uint8Array> {
    const bytes = utf8(text)
    let at = 0
    return new ReadableStream({
      pull(controller) {
        if (at >= bytes.length) return controller.close()
        controller.enqueue(bytes.slice(at, at + size))
        at += size
      },
    })
  }

  it("scrubs raw, URL-encoded, JSON-escaped and base64 echoes across chunk boundaries", async () => {
    const forms = [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1), btoa(secret), btoa(`x${secret}`).slice(2)]
    const echo = `{"a":"${forms.join('","')}"}\nbinary:\u00ff\u0000end`
    for (const size of [1, 3, 7, 64]) {
      let calls = 0
      let sentRedirect: string | null = null
      setUpstreamFetch(async (req) => {
        calls++
        sentRedirect = req.redirect
        return new Response(chunked(echo, size), {
          status: 200,
          headers: { "content-type": "application/json", "set-cookie": "s=1", "mehen-error": "1", "x-echo": secret, connection: "x-hop", "x-hop": "1" },
        })
      })
      const echoed: string[][] = []
      const res = await forwardRelay(material, null, { onEcho: (items) => echoed.push(items) })
      const text = await res.text()
      expect(calls).toBe(1)
      expect(sentRedirect).toBe("manual")
      for (const form of forms) expect(text, `chunk ${size}`).not.toContain(form.slice(0, -3))
      expect(text).toContain("[redacted:echo-item]")
      expect(text.endsWith("binary:\u00ff\u0000end")).toBe(true)
      expect(res.headers.get(ITEM_HEADER)).toBe("echo-item (alex@example.com)")
      expect(res.headers.get(UPSTREAM_HEADER)).toBe("1")
      expect(res.headers.get("set-cookie")).toBeNull()
      expect(res.headers.get("mehen-error")).toBeNull()
      expect(res.headers.get("x-hop")).toBeNull()
      expect(res.headers.get("x-echo")).toBe("[redacted:echo-item]")
      expect(echoed).toEqual([["echo-item"]])
    }
  })

  it("passes binary bodies through byte for byte", async () => {
    const bytes = new Uint8Array(256).map((_, i) => i)
    setUpstreamFetch(async () => new Response(bytes, { status: 200 }))
    const res = await forwardRelay(material, null)
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(bytes)
  })

  it("returns a redirect to the agent as is, without following it", async () => {
    const urls: string[] = []
    setUpstreamFetch(async (req) => {
      urls.push(req.url)
      return new Response(null, { status: 302, headers: { location: `https://elsewhere.example.com/?t=${encodeURIComponent(secret)}` } })
    })
    const res = await forwardRelay(material, null)
    expect(res.status).toBe(302)
    expect(urls).toEqual(["https://api.example.com/echo"])
    expect(res.headers.get("location")).toBe("https://elsewhere.example.com/?t=[redacted:echo-item]")
    expect(res.headers.get(ITEM_HEADER)).toBe("echo-item (alex@example.com)")
  })

  it("refuses a response larger than the cap and reports an unreachable upstream", async () => {
    setUpstreamFetch(async () => new Response("x", { headers: { "content-length": String(64 * 1024 * 1024) } }))
    await expect(forwardRelay(material, null)).rejects.toMatchObject({ code: "too_large" })
    setUpstreamFetch(async () => {
      throw new Error("dns")
    })
    await expect(forwardRelay(material, null)).rejects.toMatchObject({ code: "upstream_failed" })
  })
})

describe("relay route", () => {
  it("needs a device proof", async () => {
    const res = await fetchWorker("/v1/relay", { method: "POST", body: JSON.stringify(request()) })
    expect(res.status).toBe(401)
    expect(res.headers.get("mehen-error")).toBe("1")
  })
})
