import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { base64UrlEncode, utf8 } from "@mehen/protocol"
import { getTemplate } from "@mehen/protocol/templates"
import { VaultError } from "../src/http.ts"
import { forwardRelay } from "../src/relay/forward.ts"
import { setRelayServices } from "../src/relay/services.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import { freshTenant } from "./helpers.ts"
import { policyFixture } from "./policy-fixtures.ts"

// The relay end to end for the providers added with the read allowlists:
// each item is stored with its template's binding and injection but with a
// policy of its own that allows everything, so only the template's floors
// (held per host by the protocol) stand between the agent and the
// provider. Every documented sensitive operation must still be held for a
// person or refused, before any secret is opened and with no upstream
// call. The protocol's template tests make the same check at the resolver
// (underBroadAllow); this one runs the relay itself.
beforeEach(() => {
  setRelayServices({ async reviewRequest() { throw new VaultError("approval_required", "Review this request.", { next: { say: "Ask a human to review this request." } }) } })
})
afterEach(() => {
  setRelayServices({})
  setUpstreamFetch(null)
})
const inVault = async (test: (ctx: import("../src/vault/core.ts").VaultContext) => Promise<void>) => runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), (instance) => test(instance.context))

// A made-up value (SENTINEL marks the tests' fake keys) the relay must never open here.
const FAKE = "SENTINEL"

type Case = [template: string, method: string, url: string, code: "approval_required" | "policy_denied", body?: unknown]

const MCP = { model: "grok-4", input: "hi", tools: [{ type: "mcp", server_url: "https://evil.test/mcp", server_label: "evil" }] }

const CASES: Case[] = [
  ["huggingface", "GET", "https://huggingface.co/api/models/acme/model/jwt", "approval_required"],
  ["huggingface", "GET", "https://huggingface.co/api/models/acme/model/xet-read-token/main", "approval_required"],
  ["huggingface", "GET", "https://huggingface.co/api/spaces/acme/space/secrets", "approval_required"],
  ["huggingface", "POST", "https://huggingface.co/api/settings/webhooks", "policy_denied", { url: "https://evil.test/hook" }],
  ["huggingface", "POST", "https://huggingface.co/api/models/acme/model/resource-group", "policy_denied", { resourceGroupId: "rg" }],
  ["replicate", "POST", "https://api.replicate.com/v1/predictions", "approval_required", { version: "v1", input: {}, webhook: "https://evil.test/hook" }],
  ["replicate", "GET", "https://api.replicate.com/v1/webhooks/default/secret", "approval_required"],
  ["xai", "GET", "https://api.x.ai/v1/responses/r1", "approval_required"],
  ["xai", "POST", "https://api.x.ai/v1/responses", "approval_required", MCP],
  ["xai", "GET", "https://api.x.ai/v1/api-key", "approval_required"],
  ["supabase", "GET", "https://api.supabase.com/v1/projects/ref/api-keys", "approval_required"],
  ["supabase", "GET", "https://api.supabase.com/v1/branches/br1", "approval_required"],
  ["supabase", "POST", "https://api.supabase.com/v1/projects/ref/api-keys", "policy_denied", { type: "secret" }],
  ["digitalocean", "GET", "https://api.digitalocean.com/v2/kubernetes/clusters/c1/kubeconfig", "approval_required"],
  ["digitalocean", "GET", "https://api.digitalocean.com/v2/databases/db1/pools", "approval_required"],
  ["digitalocean", "POST", "https://api.digitalocean.com/v2/account/keys", "policy_denied", { name: "k", public_key: "ssh-ed25519 AAAA" }],
  ["railway", "POST", "https://backboard.railway.com/graphql/v2", "approval_required", { query: "query { variables(projectId: \"p\", environmentId: \"e\") }" }],
  ["render", "GET", "https://api.render.com/v1/services/srv/env-vars", "approval_required"],
  ["render", "GET", "https://api.render.com/v1/webhooks", "approval_required"],
  ["render", "POST", "https://api.render.com/v1/webhooks", "policy_denied", { url: "https://evil.test/hook" }],
  ["upstash", "GET", "https://api.upstash.com/v2/redis/databases", "approval_required"],
  ["upstash", "POST", "https://api.upstash.com/v2/teams/member", "policy_denied", { team_id: "t", member_email: "x@evil.test" }],
  ["planetscale", "GET", "https://api.planetscale.com/v1/organizations/acme/databases/db/branches/main/roles", "approval_required"],
  ["planetscale", "POST", "https://api.planetscale.com/v1/organizations/acme/service-tokens", "policy_denied", { name: "t" }],
]

describe("the new providers' sensitive operations at the relay, with the item's own policy allowing everything", () => {
  it.each(CASES)("%s %s %s is %s", async (id, method, url, code, body) => inVault(async (ctx) => {
    const template = getTemplate(id)
    if (!template) throw new Error(id)
    const basic = template.kind === "basic-auth"
    const device = await policyFixture(ctx, {
      slug: `${id}-key`,
      kind: template.kind,
      provider: id,
      binding: template.binding,
      injection: template.injection,
      ceiling: "relay",
      policy: { default: "allow", rules: [{ action: "allow", paths: ["/**"], note: "everything" }] },
      publicFields: basic ? { username: "agent@example.com" } : {},
      secretFields: basic ? { password: FAKE } : { key: FAKE },
    })
    let sends = 0
    let opens = 0
    setUpstreamFetch(async () => {
      sends++
      return new Response("should not send")
    })
    const guarded = { ...ctx, openField: async (...args: Parameters<typeof ctx.openField>) => { opens++; return ctx.openField(...args) } }
    const input = {
      item: `${id}-key`,
      method,
      url,
      headers: body === undefined ? [] : [["content-type", "application/json"]],
      ...(body === undefined ? {} : { body: base64UrlEncode(utf8(JSON.stringify(body))) }),
    }
    await expect(authoriseRelay(guarded, device, input).then((material) => forwardRelay(material, null))).rejects.toMatchObject({ code })
    expect(opens).toBe(0)
    expect(sends).toBe(0)
  }))
})

describe("the body floors at the relay", () => {
  it.each([
    ["xai", "https://api.x.ai/v1/responses", { model: "grok-4", input: "hi", tools: [{ type: "web_search" }] }],
    ["replicate", "https://api.replicate.com/v1/predictions", { version: "v1", input: { prompt: "a cat" } }],
  ] as const)("let a plain %s call through to the provider, once", async (id, url, body) => inVault(async (ctx) => {
    const template = getTemplate(id)
    if (!template) throw new Error(id)
    const device = await policyFixture(ctx, { slug: `${id}-key`, kind: template.kind, provider: id, binding: template.binding, injection: template.injection, ceiling: "relay", policy: template.policy, secretFields: { key: FAKE } })
    let sends = 0
    setUpstreamFetch(async () => {
      sends++
      return new Response("{}", { headers: { "content-type": "application/json" } })
    })
    await authoriseRelay(ctx, device, { item: `${id}-key`, method: "POST", url, headers: [["content-type", "application/json"]], body: base64UrlEncode(utf8(JSON.stringify(body))) }).then((material) => forwardRelay(material, null))
    expect(sends).toBe(1)
  }))
})
