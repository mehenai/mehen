import { createExecutionContext } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { expect, it } from "vitest"
import worker from "../src/index.ts"

it("associates only the native gate callback with the configured Apple apps", async () => {
  const response = await worker.fetch(new Request("https://vault.test/.well-known/apple-app-site-association"), { ...env, APPLE_WEBCREDENTIAL_APPS: " ABCDE12345.com.example.app , ABCDE12345.com.example.other " }, createExecutionContext())
  expect(response.status).toBe(200)
  expect(response.headers.get("content-type")).toBe("application/json")
  expect(response.headers.has("location")).toBe(false)
  expect(await response.json()).toEqual({ webcredentials: { apps: ["ABCDE12345.com.example.app", "ABCDE12345.com.example.other"] }, applinks: { apps: [], details: ["ABCDE12345.com.example.app", "ABCDE12345.com.example.other"].map(appID => ({ appID, paths: ["/app/v1/gate/callback"] })) } })
  const missing = await worker.fetch(new Request("https://vault.test/.well-known/apple-app-site-association"), { ...env, APPLE_WEBCREDENTIAL_APPS: " " }, createExecutionContext())
  expect(missing.status).toBe(404)
  expect(await missing.json()).toEqual({ error: "not_found", message: "No such route." })
})

// The disclosure contact (RFC 9116), as mehen.dev and docs.mehen.dev serve
// it, naming this host as its canonical URL.
it("/.well-known/security.txt names the contact, the policy and this host, as plain text", async () => {
  const get = (method = "GET") => worker.fetch(new Request(`${env.VAULT_ORIGIN}/.well-known/security.txt`, { method }), env, createExecutionContext())
  const response = await get()
  expect(response.status).toBe(200)
  expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8")
  expect(response.headers.get("cache-control")).toBe("public, max-age=300")
  expect(response.headers.get("x-content-type-options")).toBe("nosniff")
  expect(response.headers.has("location")).toBe(false)
  const text = await response.text()
  expect(text).toContain("Contact: mailto:security@mehen.dev\n")
  expect(text).toContain("Policy: https://docs.mehen.dev/security/disclosure\n")
  expect(text).toContain("Preferred-Languages: en\n")
  expect(text).toContain(`Canonical: ${env.VAULT_ORIGIN}/.well-known/security.txt\n`)
  // RFC 9116 needs an Expires in the future: renew it, with apps/web's and apps/docs', when this fails.
  expect(Date.parse(/^Expires: (.+)$/m.exec(text)?.[1] ?? "")).toBeGreaterThan(Date.now())
  const head = await get("HEAD")
  expect(head.status).toBe(200)
  expect(await head.text()).toBe("")
  const post = await get("POST")
  expect(post.status).toBe(405)
  expect(post.headers.get("mehen-error")).toBe("1")
})
