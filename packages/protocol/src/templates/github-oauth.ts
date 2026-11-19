import type { OAuthProviderTemplate, SensitiveEndpoint } from "../templates.ts"
import { ACCESS_TOKEN_BEARER, GITHUB_ALLOWED, GITHUB_SENSITIVE, type PolicyRuleInput } from "./shared.ts"

const toSensitiveEndpoint = (r: PolicyRuleInput): SensitiveEndpoint => ({
  action: r.action === "deny" ? "deny" : "approve",
  ...(r.methods ? { methods: r.methods } : {}),
  paths: r.paths ?? ["/**"],
  ...(r.body ? { body: r.body } : {}),
  why: r.note ?? "sensitive",
})

// The same rules as the GitHub personal access token (GITHUB_ALLOWED and
// GITHUB_SENSITIVE).
export const githubOauth: OAuthProviderTemplate = {
  id: "github-oauth",
  family: "github",
  displayName: "GitHub",
  category: "code",
  docsUrl: "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
  clientTemplate: "github-oauth-client",
  auth: {
    kind: "oauth2",
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    pkce: "S256",
    clientAuth: "client_secret_post",
    tokenRequestFormat: "form",
    scopes: {
      separator: " ",
      param: "scope",
      identity: [],
      identityScopes: [],
      defaults: ["repo", "read:user"],
      allowed: ["repo", "public_repo", "read:user", "user:email", "read:org", "gist", "notifications", "workflow", "read:project", "project"],
    },
    authorizeParams: { prompt: "select_account" },
    accountHint: { param: "login" },
    tokenResponse: { accessToken: "access_token", refreshToken: "refresh_token", expiresIn: "expires_in", refreshTokenExpiresIn: "refresh_token_expires_in", grantedScopes: "scope" },
  },
  identity: { from: "request", request: { method: "GET", url: "https://api.github.com/user", headers: { accept: "application/vnd.github+json" } }, subject: "id", label: "login" },
  upstream: { baseUrl: "https://api.github.com", binding: { hosts: ["api.github.com"] }, injection: ACCESS_TOKEN_BEARER },
  // OAuth app tokens do not expire but are revoked after a year unused.
  refresh: { mode: "never_expires", rotation: "strict", marginSeconds: 300, terminalErrors: ["invalid_grant", "bad_refresh_token"], clientErrors: ["invalid_client", "incorrect_client_credentials", "unauthorized_client"] },
  lifetimes: { refreshTokenIdleSeconds: 365 * 86_400 },
  defaultPolicy: { default: "approve", rules: GITHUB_ALLOWED },
  sensitiveEndpoints: GITHUB_SENSITIVE.map(toSensitiveEndpoint),
}
