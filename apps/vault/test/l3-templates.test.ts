import { describe, expect, it } from "vitest"
import { BindingSchema, InjectionSchema, PolicySchema } from "@mehen/protocol/api"
import { OAUTH_PROVIDERS, checkBinding, connectionPolicy, evaluatePolicy, getTemplate, normaliseScope, parseDestination, validHostPattern } from "@mehen/protocol"

function decide(policy: ReturnType<typeof connectionPolicy>, method: string, url: string) {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(url)
  return evaluatePolicy(policy, parsed.destination).action
}

describe("OAuth provider templates", () => {
  const providers = Object.values(OAUTH_PROVIDERS)

  it("covers the required providers", () => {
    expect(Object.keys(OAUTH_PROVIDERS)).toEqual(expect.arrayContaining(["google-gmail", "google-calendar", "google-drive", "github-oauth", "microsoft-graph"]))
    for (const id of ["google-gmail", "google-calendar", "google-drive"]) expect(OAUTH_PROVIDERS[id]?.clientTemplate).toBe("google-oauth-client")
  })

  it.each(providers.map((p) => [p.id, p] as const))("%s sends its client secret only where its client binding allows", (_id, provider) => {
    const client = getTemplate(provider.clientTemplate)
    expect(client?.kind).toBe("oauth-client")
    const token = parseDestination("POST", provider.auth.tokenUrl)
    expect(token.ok && client && checkBinding(client.binding, token.destination).ok).toBe(true)
    for (const url of [provider.auth.authorizeUrl, provider.auth.tokenUrl, provider.upstream.baseUrl, provider.identity.request?.url ?? "https://x.example"]) expect(url.startsWith("https://")).toBe(true)
    expect(BindingSchema.safeParse(provider.upstream.binding).success).toBe(true)
    for (const host of provider.upstream.binding.hosts) expect(validHostPattern(host)).toBe(true)
    expect(InjectionSchema.safeParse(provider.upstream.injection).success).toBe(true)
    expect(PolicySchema.safeParse(connectionPolicy(provider)).success).toBe(true)
    for (const scope of provider.auth.scopes.defaults) expect(normaliseScope(provider, scope)).toBe(scope)
    expect(provider.refresh.terminalErrors).toContain("invalid_grant")
  })

  it("Gmail denies forwarding, delegates, filters, send-as and settings writes, and approves sends", () => {
    const gmail = OAUTH_PROVIDERS["google-gmail"]
    if (!gmail) throw new Error("gmail")
    const policy = connectionPolicy(gmail)
    const base = "https://gmail.googleapis.com/gmail/v1/users/me"
    for (const path of ["/settings/forwardingAddresses", "/settings/autoForwarding", "/settings/delegates", "/settings/filters", "/settings/sendAs", "/settings/sendAs/alias@example.com", "/settings/imap", "/settings/vacation"]) {
      for (const method of ["POST", "PUT", "PATCH", "DELETE"]) expect(decide(policy, method, base + path), `${method} ${path}`).toBe("deny")
    }
    expect(decide(policy, "GET", `${base}/settings/filters`)).toBe("allow")
    expect(decide(policy, "POST", `${base}/messages/send`)).toBe("approve")
    expect(decide(policy, "POST", `${base}/drafts/send`)).toBe("deny")
    expect(decide(policy, "POST", "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send")).toBe("approve")
    expect(decide(policy, "POST", `${base}/drafts`)).toBe("allow")
    expect(normaliseScope(gmail, "gmail.modify")).toBe("https://www.googleapis.com/auth/gmail.modify")
    expect(normaliseScope(gmail, "https://mail.google.com/")).toBeNull()
  })

  it("GitHub and Graph keep their persistence routes closed", () => {
    const github = connectionPolicy(OAUTH_PROVIDERS["github-oauth"] as NonNullable<(typeof OAUTH_PROVIDERS)[string]>)
    expect(decide(github, "POST", "https://api.github.com/repos/a/b/keys")).toBe("deny")
    expect(decide(github, "POST", "https://api.github.com/repos/a/b/hooks")).toBe("deny")
    expect(decide(github, "GET", "https://api.github.com/user/repos")).toBe("allow")
    const graph = connectionPolicy(OAUTH_PROVIDERS["microsoft-graph"] as NonNullable<(typeof OAUTH_PROVIDERS)[string]>)
    expect(decide(graph, "POST", "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules")).toBe("deny")
    expect(decide(graph, "PATCH", "https://graph.microsoft.com/v1.0/me/mailboxSettings")).toBe("deny")
    expect(decide(graph, "POST", "https://graph.microsoft.com/v1.0/me/sendMail")).toBe("approve")
    expect(decide(graph, "GET", "https://graph.microsoft.com/v1.0/me/messages")).toBe("allow")
  })
})
